class System:
    def __init__(self, nbNodes, nbSecrets, secrets, nodes, fallbackActions, stolenSecrets, nodesStates, NodesKernels, resultStructure):
        self.nbNodes = nbNodes
        self.nbSecrets = nbSecrets
        self.secrets = secrets
        self.nodes = nodes
        self.fallbackActions = fallbackActions
        self.stolenSecrets = stolenSecrets 
        self.nodesStates = nodesStates  
        self.NodesKernels = NodesKernels
        self.resultStructure = resultStructure