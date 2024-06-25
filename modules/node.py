class node:
    def __init__(self, id, name, softwareClass, text, kernelIndex, nbRoles, nbInputs, nodeType, plausThreshold, actThreshold, secrTheftCost, debug_fallbackActionNames, secrStore, monBypassCost, roles, inputs, fallbackActionIndex):
        self.id = id
        self.name = name
        self.softwareClass = softwareClass
        self.text = text
        self.kernelIndex = kernelIndex
        self.nbRoles = nbRoles
        self.nbInputs = nbInputs
        self.nodeType = nodeType
        self.plausThreshold = plausThreshold
        self.actThreshold = actThreshold
        self.secrTheftCost = secrTheftCost
        self.debug_fallbackActionNames = debug_fallbackActionNames
        self.secrStore = secrStore
        self.monBypassCost = monBypassCost
        self.roles = roles
        self.inputs = inputs
        self.fallbackActionIndex = fallbackActionIndex
