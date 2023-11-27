import sys, logging
import cyberbattle.simulation.model as model
import cyberbattle.simulation.commandcontrol as commandcontrol
import cyberbattle.samples.toyctf.toy_ctf as ctf
logging.basicConfig(stream=sys.stdout, level=logging.INFO, format="%(levelname)s: %(message)s")

'''
You start with the client node and you are trying to own 7 more nodes in the toyctf enviroment network,
lets look at the visual of our enviroment and see what the red-hat agent "sees"

- CMD - dbg.plot_discovered_network() 

Keep in mind this is how the enviroment stores the node 'client' and its properties below, this
information can be obtained from the debugger by running

- CMD - dbg.get_node_information('client')

====================== NodeInfo Class INFO ===============================

This class represents information about a node in a cyber simulation.

Parameters:
- services: List of services on the node.
- vulnerabilities: Dictionary of vulnerabilities on the node.
- value: Numeric value associated with the node.
- properties: List of properties associated with the node.
- firewall: Firewall configuration for the node.
- agent_installed: Boolean indicating whether an agent is installed on the node.
- privilege_level: Privilege level of the node.
- reimagable: Boolean indicating whether the node is reimagable.
- last_reimaging: Timestamp of the last reimaging.
- owned_string: String indicating ownership status.
- sla_weight: Weight for Service Level Agreement (SLA).

Note: Ensure that the required classes (VulnerabilityInfo, VulnerabilityType, Rates, FirewallConfiguration,
      FirewallRule, RulePermission, PrivilegeLevel) are properly imported from cyberbattle.simulation.model.

====================== NodeInfo Class INFO ================================

========================= Example Node ['client'] =========================

    'client': m.NodeInfo(
        services=[],
        value=0,
        vulnerabilities=dict(
            SearchEdgeHistory=m.VulnerabilityInfo(
                description="Search web history for list of accessed websites",
                type=m.VulnerabilityType.LOCAL,
                outcome=m.LeakedNodesId(["Website"]),
                reward_string="Web browser history revealed website URL of interest",
                cost=1.0
            )),
        agent_installed=True,
        reimagable=False),
    }

========================= Example Node ['client'] =========================

There 3 types of "actions", Local Vulnerability, Remote Vulnerability, and Connect,
the description of each action is seen below,

 Actions
    -------

    Actions are of the form:

        (kind, *indicators)


    The ``kind`` which is one of

        # kind
        0: Local Vulnerability
        1: Remote Vulnerability
        2: Connect

    The indicators vary in meaning and length, depending on the ``kind``:

        # kind=0 (Local Vulnerability)
        indicators = (node_id, local_vulnerability_id)

        # kind=1 (Remote Vulnerability)
        indicators = (from_node_id, to_node_id, remote_vulnerability_id)

        # kind=2 (Connect)
        indicators = (from_node_id, to_node_id, port_id, credential_id)

    The node ids can be obtained from the graph, e.g.

        node_ids = observation['graph'].keys()

    The other example indicators are listed below.

        # local_vulnerability_ids
        0: ScanBashHistory
        1: ScanExplorerRecentFiles
        2: SudoAttempt
        3: CrackKeepPassX
        4: CrackKeepPass
        5: SearchEdgeHistory

        # remote_vulnerability_ids
        0: ProbeLinux
        1: ProbeWindows

        # port_ids
        0: HTTPS
        1: GIT
        2: SSH
        3: RDP
        4: PING
        5: MySQL
        6: SSH-key
        7: su

    Examples
    ~~~~~~~~
    Here are some example actions:

    .. code:: python

        a = (0, 5, 3)        # try local vulnerability "CrackKeepPassX" on node 5
        a = (1, 5, 7, 1)     # try remote vulnerability "ProbeWindows" from node 5 to node 7
        a = (2, 5, 7, 3, 2)  # try to connect from node 5 to node 7 using credential 2 over RDP port

    Now lets try a attack, we can view possible action by running the command
    
    CMD - c2.print_all_attacks()

    We see that node "client" has the local attack action of "SearchEdgeHistory", therefore 
    lets run the attack by running the command

    CMD - c2.run_attack('client', 'SearchEdgeHistory')

    After the attack, we discovered the node 'Website' on the network, run the visual dbg.plot_discovered_network() 
    to see that the 'Website is now seen. Now we can rerun the command c2.print_all_attacks() to see other possible 
    action that can be taken by the agent.

    CMD - c2.print_all_attacks()

    ================================================ Output ================================================ 
    id                                                                                    
    client        owned         []  [SearchEdgeHistory]                                 []
    Website  discovered        NaN                 None  [ScanPageContent, ScanPageSource]
    ================================================ Output ================================================ 

    Now lets try do a remote attack action on node 'Website' and see what infomation we can obtain,

    CMD - c2.run_remote_attack('client', 'Website', 'ScanPageContent')

    ================================================ Output ================================================ 
    INFO: discovered node: GitHubProject
    INFO: GOT REWARD: WEBSITE page content has a link to github -> Github project discovered!
    <cyberbattle.simulation.model.LeakedNodesId object at 0x12a4e4b20>
    ================================================ Output ================================================ 

    We notice that this remote attack action helpped the red-hat agent discover the node "GitHubProject"
    and got a reward from it. And if we run dbg.plot_discovered_network(), we should see the node GitHubProject

    CMD - dbg.plot_discovered_network()

    Lets keep on doing action till we can 'own' a node other than client,

    CMD - c2.run_remote_attack('client', 'GitHubProject', 'CredScanGitHistory')

    ================================================ Output ================================================ 
    INFO: discovered node: AzureStorage
    INFO: discovered credential: CachedCredential(node='AzureStorage', port='HTTPS', credential='SASTOKEN1')
    INFO: GOT REWARD: CredScan success: Some secure access token (SAS) was leaked in a reverted git commit
    ================================================ Output ================================================ 

    We notice that we have gotten the credential ('SASTOKEN1') from the node 'AzureStorage' that we are going to exploit,
    to view the avaiable credentials to the agent we run,  

    - CMD - c2.credentials_gathered_so_far

    ================================================ Output ================================================ 
    {CachedCredential(node='AzureStorage', port='HTTPS', credential='SASTOKEN1')}
    ================================================ Output ================================================ 

    Now we can try connecting to that node "AzureStorage", and we do this by running the connect action,

    - CMD - c2.connect_and_infect('client', 'AzureStorage', 'HTTPS', 'SASTOKEN1')

    ================================================ Output ================================================ 
    INFO: Infected node 'AzureStorage' from 'client' via HTTPS with credential 'SASTOKEN1'
    True
    ================================================ Output ================================================ 

    Lets see how the visual network looks like, we will notice that the 'AzureStorage' node is red indicting 
    that the node has be taken over by the red-hat agent. 

    - CMD - dbg.plot_discovered_network()

    Now let try other actions by the red-hat agent and seeing what's aviable by running 

    - CMD - c2.print_all_attacks()
    - CMD - c2.run_remote_attack('client', 'Website', 'ScanPageSource')

    Now we have discovered the node "Website.Directory"

    - CMD - dbg.plot_discovered_network()
    - CMD - c2.print_all_attacks()

    We can try doing more remote attack actions,

    - CMD - c2.run_remote_attack('client', 'Website.Directory', 'NavigateWebDirectoryFurther')

    ================================================ Output ================================================ 
    INFO: discovered node: Website
    INFO: discovered credential: CachedCredential(node='Website', port='MySQL', credential='ReusedMySqlCred-web')
    INFO: GOT REWARD: Discover browseable web directory: Navigating to parent URL revealed file `readme.txt`with secret data (aflag); and `getting-started.txt` with MYSQL credentials
    <cyberbattle.simulation.model.LeakedCredentials object at 0x12a4e4cd0>
    ================================================ Output ================================================

    Looks like we found another credential for the node 'Website', now try to infect that node 'Website' with
    the credential 'ReusedMySqlCred-web'

    - CMD - c2.connect_and_infect('client', 'Website', 'MySQL', 'ReusedMySqlCred-web')

    ================================================ Output ================================================ 
    INFO: BLOCKED TRAFFIC: source node 'client' is blocking outgoing traffic on port 'MySQL'
    False
    ================================================ Output ================================================ 

    Seems like the connection is blocked by the firewall, now lets try running more remote attacks,

    - CMD - c2.run_remote_attack('client', 'Website.Directory', 'NavigateWebDirectory')

    A new node is discovered named 'Sharepoint', let look at it

    - CMD - dbg.plot_discovered_network()
    - CMD - c2.print_all_attacks()

    Lets try attacking 'Sharepoint', 

    - CMD - c2.run_remote_attack('client', 'Sharepoint', 'ScanSharepointParentDirectory')

    A credential is revealed from node 'AzureResourceManager' via port 'HTTPS' with the value 'ADPrincipalCreds',
    now lets try to connect and infect 'AzureResourceManager' by running the command,

    - CMD - c2.connect_and_infect('client', 'AzureResourceManager', 'HTTPS', 'ADPrincipalCreds')

    ================================================ Output ================================================ 
    INFO: Infected node 'AzureResourceManager' from 'client' via HTTPS with credential 'ADPrincipalCreds'
    INFO: Owned message: FLAG: Shared credentials with database user - Obtained secrets hidden in Azure Managed Resources
    True
    ================================================ Output ================================================ 

    We have sucessfully infected 'AzureResourceManager', lets see how our network looks,

    - CMD - dbg.plot_discovered_network()
    - CMD - c2.print_all_attacks()

    ================================================ Output ================================================ 
                                status                     properties        local_attacks                                     remote_attacks
    id                                                                                                                                     
    client                     owned                             []  [SearchEdgeHistory]                                                 []
    AzureStorage               owned   [CTFFLAG:LeakedCustomerData]                   []                           [AccessDataWithSASToken]
    AzureResourceManager       owned  [CTFFLAG:LeakedCustomerData2]                   []                               [ListAzureResources]
    Website               discovered                            NaN                 None                  [ScanPageContent, ScanPageSource]
    GitHubProject         discovered                            NaN                 None                               [CredScanGitHistory]
    Website.Directory     discovered                            NaN                 None  [NavigateWebDirectoryFurther, NavigateWebDirec...
    Sharepoint            discovered                            NaN                 None                    [ScanSharepointParentDirectory]
    ================================================ Output ================================================ 

    We notice that we now own 3 nodes ['client', 'AzureStorage', 'AzureResourceManager'] and all the possible local and remote attacks we can 
    perform.

    - CMD - c2.run_remote_attack('client', 'AzureResourceManager', 'ListAzureResources')
    - CMD - print(c2.credentials_gathered_so_far)
    - CMD - c2.connect_and_infect('client', 'Website', 'SSH', 'ReusedMySqlCred-web')

    ================================================ Output ================================================ 
    INFO: Infected node 'Website' from 'client' via SSH with credential 'ReusedMySqlCred-web'
    INFO: Owned message: FLAG: Login using insecure SSH user/password
    True
    ================================================ Output ================================================ 

    We have successfully infected the 'Website' node, let try to do a local attack on 'Website'

    - CMD - c2.run_attack('Website', 'CredScanBashHistory')

    ================================================ Output ================================================ 
    INFO: discovered node: Website[user=monitor]
    INFO: discovered credential: CachedCredential(node='Website[user=monitor]', port='SSH', credential='monitorBashCreds')
    INFO: GOT REWARD: FLAG: SSH history revealed credentials for the monitoring user (monitor)
    ================================================ Output ================================================ 

    We discovered a new node and some more credetial we can try to exploit by connecting to 'Website[user=monitor]',
    lets try run the connect action,

    - CMD - dbg.plot_discovered_network()
    - CMD - print(c2.credentials_gathered_so_far)
    - CMD - c2.print_all_attacks()
    - CMD - c2.connect_and_infect('client', 'Website[user=monitor]', 'SSH', 'monitorBashCreds')

    ================================================ Output ================================================ 
    INFO: BLOCKED TRAFFIC: target node 'Website[user=monitor]' is blocking outgoing traffic on port 'SSH'
    False
    ================================================ Output ================================================ 

    It failed because traffic is blocked on the port 'SSH', we haven't talked about reward that the agent has,
    the total reward that the red-hat agent has accumlated is seen by the command,

    - CMD - c2.total_reward()
    ================================================ Output ================================================ 
    246.0 (might vary for you)
    ================================================ Output ================================================ 

    We can notice that each of our action either give a positive or negative reward, for example trying to 
    connect to a blocked node will give use a negative reward as seen below,

    - CMD - c2.connect_and_infect('client', 'Website[user=monitor]', 'SSH', 'monitorBashCreds')
    - CMD - c2.total_reward()

    ================================================ Output ================================================ 
    INFO: BLOCKED TRAFFIC: target node 'Website[user=monitor]' is blocking outgoing traffic on port 'SSH'
    False
    236.0 (-10 reward for failed connection)
    ================================================ Output ================================================ 

    Since we know that a credential to the node "Website[user=monitor]" is monitorBashCreds, we can connecting 
    through different ports ['SSH', 'HTTPS', 'RDP', 'PING', 'MySQL', 'SSH-key', 'su'],

    - CMD - c2.connect_and_infect('client', 'Website[user=monitor]', 'HTTPS', 'monitorBashCreds')
    - CMD - c2.connect_and_infect('client', 'Website[user=monitor]', 'RDP', 'monitorBashCreds')
    - CMD - c2.connect_and_infect('client', 'Website[user=monitor]', 'PING', 'monitorBashCreds')
    - CMD - c2.connect_and_infect('client', 'Website[user=monitor]', 'MySQL', 'monitorBashCreds')
    - CMD - c2.connect_and_infect('client', 'Website[user=monitor]', 'SSH-key', 'monitorBashCreds')
    - CMD - c2.connect_and_infect('client', 'Website[user=monitor]', 'su', 'monitorBashCreds') (Lets try connecting from another node)
    - CMD - c2.connect_and_infect('Website', 'Website[user=monitor]', 'su', 'monitorBashCreds')

    ================================================ Output ================================================ 
    INFO: target node 'Website[user=monitor]' not listening on port 'HTTPS'
    False
    INFO: target node 'Website[user=monitor]' not listening on port 'RDP'
    False
    INFO: BLOCKED TRAFFIC: source node 'client' is blocking outgoing traffic on port 'PING'
    False
    INFO: BLOCKED TRAFFIC: source node 'client' is blocking outgoing traffic on port 'PING'
    False
    INFO: BLOCKED TRAFFIC: source node 'client' is blocking outgoing traffic on port 'MySQL'
    False
    INFO: BLOCKED TRAFFIC: source node 'client' is blocking outgoing traffic on port 'SSH-key'
    False
    INFO: BLOCKED TRAFFIC: source node 'client' is blocking outgoing traffic on port 'su'
    False
    INFO: BLOCKED TRAFFIC: source node 'client' is blocking outgoing traffic on port 'su'
    False
    INFO: BLOCKED TRAFFIC: source node 'client' is blocking outgoing traffic on port 'su'
    False
    INFO: Infected node 'Website[user=monitor]' from 'Website' via su with credential 'monitorBashCreds'
    INFO: Owned message: FLAG User escalation by stealing credentials from bash history
    True
    ================================================ Output ================================================ 

    We can see that there can be numerous combinations needed to try to infect a node even when you know the
    credentials. Lets see our visual and the reward we have now. 

    - CMD - dbg.plot_discovered_network()
    - CMD - c2.total_reward()
    - CMD - c2.print_all_attacks()

    Let's try a local attack now on "Website[user=monitor]" and see more information that we can get,

    - CMD - c2.run_attack("Website[user=monitor]", "CredScan-HomeDirectory")

    ================================================ Output ================================================ 
    INFO: discovered node: AzureResourceManager[user=monitor]
    INFO: discovered credential: CachedCredential(node='AzureResourceManager[user=monitor]', port='HTTPS', credential='azuread_user_credentials')
    INFO: GOT REWARD: SSH: cat ~/azurecreds.txt (running as monitor) revealed Azure user credential!
    ================================================ Output ================================================ 

    More credentials! We try to infect "AzureResourceManager[user=monitor]"

    - CMD - dbg.plot_discovered_network()
    - CMD - c2.connect_and_infect('Website[user=monitor]', 'AzureResourceManager[user=monitor]', 'HTTPS', 'azuread_user_credentials')

    ================================================ Output ================================================ 
    INFO: Infected node 'AzureResourceManager[user=monitor]' from 'Website[user=monitor]' via HTTPS with credential 'azuread_user_credentials'
    INFO: Owned message: More secrets stolen when logged as interactive `monitor` user in Azure with `az`
    True
    ================================================ Output ================================================ 

    - CMD - dbg.plot_discovered_network()
    - CMD - c2.print_all_attacks()
    - CMD - c2.total_reward()

    Now we have solved the environment by compromising a total of 6 nodes within the network, we can look at the properties of each node to see
    what was inside that node. Usually 

'''

def test(env, c2, dbg):
    while True:
        print("=========ALL KNOWN ATTACK===========")
        c2.print_all_attacks()
        print("=========ALL KNOWN NODES===========")
        c2.list_nodes() #list all know node ID by attacker
        print("=========ALL KNOWN Vulnerabilities===========")
        c2.known_vulnerabilities() #list all known vulerabilities
        print("=========All Known Credentials Given To Agent===========")
        print(c2.credentials_gathered_so_far)
        #c2.run_attack(node_id, vulerability_id) ->run an attack and attempt to exploit a vulnerability (LOCAL ATTACK)
        #c2.run_remote_attack(node_id, target_node_id, vulnerability_id) (REMOTE ATTACK)
        #c2.connect_and_infect(source_node_id, target_node_id, port_name, credentials) (Connection)
        breakpoint()
        dbg.plot_discovered_network()
        print("========================================")

if __name__ == "__main__":
    network = model.create_network(ctf.nodes)
    env = model.Environment(network=network, vulnerability_library=dict([]), identifiers=ctf.ENV_IDENTIFIERS)
    c2 = commandcontrol.CommandControl(env)
    dbg = commandcontrol.EnvironmentDebugging(c2)
    test(env, c2, dbg)
