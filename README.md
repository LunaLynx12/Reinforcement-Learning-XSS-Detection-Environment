# Reinforcement Learning XSS Detection Environment

A Gymnasium-compatible environment for training RL agents to detect XSS vulnerabilities through payload generation and testing.

## Key Features

- 🎯 **Target-Agnostic Design**: Works with any HTTP endpoint via `target_url` parameter
- 🧬 **Hybrid Payload Generation**: Template-based + mutation engine with optional LLM augmentation
- 📊 **Observable State**: 
  ```python
  observation_space = Box([status_code, is_blocked, is_vulnerable, payload_length])
  ```

- ⚖️ Ethical Controls: Built-in rate limiting (request_delay) and duplicate detection

## Quick Start
Prerequisites
```bash
pip install gymnasium stable-baselines3 requests numpy
```

## Basic Usage
```python
from xss_env import GenerativeXSSEnv

# Initialize environment
env = GenerativeXSSEnv(target_url="http://test.com/search")

# Sample action
action = np.array([1, 3, 2])  # [strategy, payload_idx, mutation_idx]
obs, reward, done, info = env.step(action)
```

## Training Modes
1. Standard Training
```bash
python xss_env.py --mode train --target http://localhost:5000/search
```

2. Hyperparameter Optimization
```bash
python xss_env.py --mode optimize --target http://localhost:5000/search
```

3. Model Testing
```bash
python xss_env.py --mode test --target http://prod.com/search --model-path xss_agent_optimized.zip
```

## Action Space
```python
action_space = MultiDiscrete([
    3,   # 0=Base payload, 1=Replay generated, 2=Generate new
    10,  # Payload index
    len(mutations)  # Mutation index
])
```

## Reward Function

|Scenario|Reward|
|---|---|
|New vulnerability found|+15.0|
|Known vulnerability|+10.0|
|Request blocked (403/5xx)|-5.0|
|Normal failed request|-0.1|

## Payload Generation
```python
# Template examples
templates = [
    "<{tag} {event}='{code}'>",
    "<iframe srcdoc=\"&lt;script&gt;{code}&lt;/script&gt;\">"
]

# Mutation examples
mutations = [
    lambda p: p.replace("(", "%28"),
    lambda p: p.upper(),
    lambda p: p.replace(" ", "/**/")
]
```

## Monitoring Output
```text
Step: 42  | Strategy: ReplayGen | Status: 200 | Vuln: True  | Reward: 15.0 | Payload: <img src=x onerror='prompt(1)'>
```

## Ethical Considerations
```python
# Always:
env = GenerativeXSSEnv(
    target_url=authorized_target,
    request_delay=0.5  # >=500ms between requests
)
```

## File Outputs
- `successful_payloads.txt`: Logs all unique vulnerable payloads
- `xss_agent_*.zip`: Saved model checkpoints