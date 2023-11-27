import cyberbattle.simulation.model as model
import cyberbattle.simulation.commandcontrol as commandcontrol
import cyberbattle.samples.toyctf.toy_ctf as ctf

def test(env, c2, dbg):
    while True:
        print("=========ALL KNOWN ATTACK===========")
        c2.print_all_attacks()
        print("=========ALL KNOWN NODES===========")
        c2.list_nodes() #list all know node ID by attacker
        print("=========ALL KNOWN Vulnerabilities===========")
        c2.known_vulnerabilities() #list all known vulerabilities
        #run_attack(node_id, vulerability_id) ->run an attack and attempt to exploit a vulnerability (LOCAL ATTACK)
        #run_remote_attack(node_id, target_node_id, vulnerability_id) (REMOTE ATTACK)
        #connect_and_infect(source_node_id, target_node_id, port_name, credentials) (Connection)
        breakpoint()
        dbg.plot_discovered_network()
        print("========================================")

if __name__ == "__main__":
    network = model.create_network(ctf.nodes)
    env = model.Environment(network=network, vulnerability_library=dict([]), identifiers=ctf.ENV_IDENTIFIERS)
    c2 = commandcontrol.CommandControl(env)
    dbg = commandcontrol.EnvironmentDebugging(c2)
    test(env, c2, dbg)
