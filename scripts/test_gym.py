import gym
import cyberbattle._env.cyberbattle_env

def loop(env):
    for i_episode in range(1):
        observation = env.reset()
        total_reward = 0
        for t in range(5600):
            action = env.sample_valid_action()
            # breakpoint()
            observation, reward, done, info = env.step(action)
            
            total_reward += reward
            
            if reward>0:
                print('####### rewarded action: {action}')
                print(f'total_reward={total_reward} reward={reward}')
                env.render()
        
            if done:
                print("Episode finished after {} timesteps".format(t+1))
                break

        env.render()

        env.close()


if __name__ == "__main__":
    env = gym.make('CyberBattleToyCtf-v0')
    loop(env)
