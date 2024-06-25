global maxCosts
maxCosts = 90

def minNoneList(list):
    filtered_list = [x for x in list if x is not None]
    if(len(filtered_list) == 0):
        minmum_cost= None
    else:    
        minmum_cost = min(filtered_list)

    
    minRoleId = list.index(minmum_cost)

    return [minmum_cost , minRoleId]



def ProtProtectCost(mySystem, node, inputIndex, roleIndex, inputIndexInSystem, attakernel_position, attakernelerState ):

    protCost = node.inputs[inputIndex].protBreakCosts.theft #protBreakCosts.theft
    keyProtect = False
    kernelSId = mySystem.NodesKernels[inputIndexInSystem]

    if attakernelerState == 'sF':
        return None
    if attakernelerState == 'sN':
        return None
    if attakernelerState != 'sM' and attakernel_position != 'peer':
        return None

    #attakernelerState == 'sM' 
    #attakernelerState == 'sB' and attakernel_position == 'peer':

    for keyindex in range(5):
        #application protocol is set to zero if one of the protection secret is available
        if  node.roles[roleIndex].sessionProtectSecretIndex[keyindex] == True:
            kerSt = False
            if kernelSId != None:
                kerSt = mySystem.nodes[kernelSId].secrStore[keyindex]
            keyProtect = True
            if (mySystem.stolenSecrets[keyindex] == True) or (mySystem.nodes[inputIndexInSystem].secrStore[keyindex] == True) or (kerSt == True):
                protCost = 0        

    if attakernel_position == 'peer':
        if keyProtect:
            return protCost
        else:
            return 0

    return protCost


def ProtDestructCost(mySystem, node, inputIndex, roleIndex, inputIndexInSystem, attakernel_position, attakernelerState ):
    theft_bool = False

    protCostBr = node.inputs[inputIndex].protBreakCosts.destruct #protBreakCosts.Destruct
 
    protCost = node.inputs[inputIndex].protBreakCosts.theft #protBreakCosts.theft
 
    keyProtect = False
    kernelSId = mySystem.NodesKernels[inputIndexInSystem]

    if attakernelerState == 'sF':
        return [None , theft_bool]
    if attakernelerState == 'sN' and attakernel_position == 'peer':
        return [0, theft_bool]
    if attakernelerState != 'sM' and attakernel_position != 'peer':
        return [None , theft_bool]

    if protCostBr == None or (protCost != None and protCost < protCostBr):
        theft_bool = True
        protCostBr = protCost

    for i in range(5):
        #same thing as earlier application protocol is set to zero if one of the protection secret is available
        if node.roles[roleIndex].sessionProtectSecretIndex[i] == True:
            kerSt = False
            if kernelSId != None:
                kerSt = mySystem.nodes[kernelSId].secrStore[i]
                #mySystem.nodes[nodeindex].secrStore[keyindex]
            keyProtect = True
            if mySystem.stolenSecrets[i] or mySystem.nodes[inputIndexInSystem].secrStore[i] or kerSt:
                protCostBr = 0

    if attakernel_position == 'peer':
        if keyProtect:
            return [ protCostBr , theft_bool ]
        else:
            return [0, theft_bool]

    return [ protCostBr , theft_bool ]


def openFormula( mySystem, input ):
    node_names = [node.name for node in mySystem.nodes]

    isOpen = input.isOpen
    replayced = isOpen.replace('$', 's')
    splited = replayced.split('&')
    splited2 = []
    for value in splited:
        splited2.append( value.split('<>')[0].replace(" ",""))
    indexs = []
    for value in splited2:
        indexs.append(node_names.index(value))
    for i in indexs:
        if mySystem.nodesStates[i] == 'sN':
            return False
    return True


def t1FtoN( mySystem, node  ):
    NbInputs = len(node.inputs)
    NbRoles = len(node.roles)
    inputs_position = [None] * NbRoles
    protocol_breaking_cost = [None]*NbRoles
    totalMinCost = [None]*NbRoles
    
    if NbInputs <= 0:
        return None
    
    for i in range(NbInputs):
        if openFormula(mySystem, node.inputs[i] ):
            #if the input is in malware state or if it's in bad data state but in peer position
            if mySystem.nodesStates[node.inputs[i].sourceNodeIndex] == 'sM' or (mySystem.nodesStates[node.inputs[i].sourceNodeIndex]  == 'sB' and node.inputs[i].position == 'peer'):
                
                roleId = node.inputs[i].roleIndex
                attack_position = node.inputs[i].position
                attackerState = mySystem.nodesStates[node.inputs[i].sourceNodeIndex] 
                inputIndexInSystem = node.inputs[i].sourceNodeIndex

                protocol_breaking_cost[roleId] = ProtProtectCost(mySystem, node, i, roleId,  inputIndexInSystem, attack_position, attackerState)
                
                if protocol_breaking_cost[roleId] != None :
                    if node.roles[roleId].nCodeInjectCost != None:
                        totalMinCost[roleId] = protocol_breaking_cost[roleId] + node.roles[roleId].nCodeInjectCost

                inputs_position[roleId]= [i , attack_position] 

    minmum_cost_injection = minNoneList(totalMinCost)[0]
    minRoleIdInjection = minNoneList(totalMinCost)[1]
        



    # If cost is still None, return None
    if minmum_cost_injection == None:
        malware_forcing_sN_cost = None
    
    
    malware_forcing_sN_cost = minmum_cost_injection

    '''^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^'''
    '''||||||||||||||||||||||||||||||||||||||||'''

    '''END OF CONDITION 3 MALWARE INJECTION FORCING STATUS N'''
    
    # Returns the sum of costs for all inputs able to produce Non availability state (sN), None if impossible
    rolCostBdM = [None] * NbRoles
    rolOk = [False] * NbRoles  # True if a role can stay OK thanks to legitimate producers, "no system roles only" are considered
    nbOKoptional = 0
    tcost = [None] * NbRoles
    nbtocomp = 0
    bdCost = None
    tr = -1
    minNonAvailableCost = None
    mandatory_0 = False
    optional_0 = False
    compromission_mandatory_role = False
    theft_bool = [False] * NbRoles

    for i in range(NbRoles):
        rolOk[i] = True #assume all roles are ok
    for i in range(NbInputs):
        rolOk[node.inputs[i].roleIndex] = False 
        #the roles that has inputs pointing on them are not ok


    # For all "no system" inputs: we memorize potential B and M available attacker nodes and costs of non-acceptable data submissions or (for M only) session destruction, 
    #this cost 0 for peer position and session breaking for others
    sessDestruct = [None] * NbRoles
    for i in range(NbInputs):
        if openFormula(mySystem, node.inputs[i] ) and (node.roles[node.inputs[i].roleIndex].categ != None) and (node.roles[node.inputs[i].roleIndex].type != "system"):
            
            attackerState = mySystem.nodesStates[node.inputs[i].sourceNodeIndex] 

            roleId = node.inputs[i].roleIndex

            attack_position = node.inputs[i].position


            if (attackerState == 'sF') and (attack_position == 'peer'):
                #increment peer ?
                rolOk[roleId] = True
                '''the roles that has inputs pointing on them but the inputs are in peer position 
                and the the node is still functional are back to be ok'''

            #if rolCostBdM[roleId] != None:

            sessDestruct[roleId] = ProtDestructCost(mySystem, node, i, roleId, node.inputs[i].sourceNodeIndex, attack_position, attackerState)[0]
            theft_bool[roleId] = ProtDestructCost(mySystem, node, i, roleId, node.inputs[i].sourceNodeIndex, attack_position, attackerState)[1]
            
            
            if sessDestruct[roleId] != None:

                if rolCostBdM[roleId] == None:
                    rolCostBdM[roleId] = sessDestruct[roleId]

                elif sessDestruct[roleId] < rolCostBdM[roleId]:
                    rolCostBdM[roleId] = sessDestruct[roleId]

            inputs_position[roleId]=  attack_position

   

    # Min cost of mandatory roles compromissions and count of compromisable OK roles
    for aroleid in range(NbRoles):
        if node.roles[aroleid].type != 'system' and node.roles[aroleid].categ != None:
            if node.roles[aroleid].categ == 'mandatory':  # Mandatory role

                if rolOk[aroleid]== False:  # Peer Position not available or the node in not in F state
                    '''one of the mandatory roles that has inputs pointing on it but the inputs are in side or mitm position 
                    or the the node is not functional '''
                    minNonAvailableCost = 0
                    mandatory_0 = True
                    roleId_mandatory_0 = aroleid

                if rolCostBdM[aroleid] != None:
                    if ((tcost[aroleid] == None) 
                    or (rolCostBdM[aroleid] < tcost[aroleid])):
                        
                        tcost[aroleid] = rolCostBdM[aroleid]  
                    # Minimal cost of the compromissions of the mandatory role => tcost

            elif node.roles[aroleid].categ == 'optional':
                if rolOk[aroleid] == True:
                    nbOKoptional += 1


    roleId_mandatory_tcost =  minNoneList(tcost)[1]
    tcost = minNoneList(tcost)[0]

    roleId_optional_0 = []
    if nbOKoptional < node.actThreshold:
        minNonAvailableCost = 0  # Not enough of optional roles are active
        optional_0 = True
        for aroleid in rolOk:
            if rolOk[aroleid] == True:
                roleId_optional_0.append(aroleid)
        




    # nbOKoptional > node.actThreshold:
    nbtocomp = 1 + nbOKoptional - node.actThreshold  # Nonember of operational roles necessary to compromise
    roleId_optional_compromission = []
    # Minimal cost of the non-mandatory roles' compromission
    for aroleid in range(NbRoles):
        tr1 = None
        j = None
        # Choice of a role with the minimal cost
        for aroleid in range(NbRoles):
            if (node.roles[aroleid].type != 'system') and (node.roles[aroleid].categ == 'optional') and (rolCostBdM[aroleid] != None) and (tr < nbtocomp):
                # Only non-mandatory roles
                if (tr1 == None) or (tr1 > rolCostBdM[aroleid]):
                    tr1 = rolCostBdM[aroleid]
                    j = aroleid  # Role of min cost
                    
        if tr1 != None:
            tr += 1

            if bdCost != None :
                bdCost = bdCost 
            else:
                bdCost= 0 + tr1
            rolCostBdM[j] = None

        roleId_optional_compromission.append(j)

    if ( minNonAvailableCost != 0):

        if tr < nbtocomp:
            minNonAvailableCost = tcost  # Impossible to compromise enough of no-mandatory roles
        if tcost == None:
            minNonAvailableCost = bdCost  # It was impossible to compromise mandatory roles

        if(bdCost != None and tcost != None): # Choice between costs of mandatory or non-mandatory role compromissions
            if(bdCost < tcost):
                minNonAvailableCost = bdCost
            else:
                minNonAvailableCost =  tcost
        else:
            minNonAvailableCost =  None
            
        if (minNonAvailableCost != None) and (minNonAvailableCost ) > maxCosts:
            minNonAvailableCost =  None

#returning  malware_forcing_sN_cost
    if (minNonAvailableCost == None) :

        #increase one for nCodeInjectCostK
        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].nCodeInjectCostK += 1 
        #increase protBreakCost counter
        if(theft_bool[minRoleIdInjection]):
            #increase one for protBreakCost.theft
            if(inputs_position[minRoleIdInjection] == 'peer'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.theftStatistics.peer  += 1 
            elif(inputs_position[minRoleIdInjection] == 'mitm'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.theftStatistics.mitm  += 1 
            elif(inputs_position[minRoleIdInjection] == 'side'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.theftStatistics.side  += 1 
            else: 
                pass
        else:
            #increase one for protBreakCost.destruct
            if(inputs_position[minRoleIdInjection] == 'peer'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.destructStatistics.peer  += 1 
            elif(inputs_position[minRoleIdInjection] == 'mitm'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.destructStatistics.mitm  += 1 
            elif(inputs_position[minRoleIdInjection] == 'side'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.destructStatistics.side  += 1 
            else: 
                pass
        return malware_forcing_sN_cost
    
#returning minNonAvailableCost 
    if (malware_forcing_sN_cost == None):
        if(minNonAvailableCost == 0):
            #increase one for costZero
            if(mandatory_0):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_0].costZero += 1
            if(optional_0):
                for optional_role_id in roleId_optional_0:
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].costZero += 1

        elif(minNonAvailableCost == tcost):
            #tcost means compromission_mandatory_role
            if(theft_bool[roleId_mandatory_tcost]):
                #increase one for protBreakCost.theft
                if(inputs_position[roleId_mandatory_tcost] == 'peer'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(inputs_position[roleId_mandatory_tcost] == 'mitm'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(inputs_position[roleId_mandatory_tcost] == 'side'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass
            else:
                #increase one for protBreakCost.destruct 
                if(inputs_position[minRoleIdInjection] == 'peer'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.destructStatistics.peer  += 1 
                elif(inputs_position[minRoleIdInjection] == 'mitm'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.destructStatistics.mitm  += 1 
                elif(inputs_position[minRoleIdInjection] == 'side'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.destructStatistics.side  += 1 
                else: 
                    pass
            
        elif(minNonAvailableCost == bdCost):
            #bdcost means compromission_optional_roles
            for optional_role_id in roleId_optional_compromission:
                if(theft_bool[optional_role_id]):
                    #increase one for protBreakCost.theft
                    if(inputs_position[optional_role_id] == 'peer'):
                         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(inputs_position[optional_role_id] == 'mitm'):
                         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(inputs_position[optional_role_id] == 'side'):
                         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass
                else:
                    #increase one for protBreakCost.destruct 
                    if(inputs_position[optional_role_id] == 'peer'):
                         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.destructStatistics.peer  += 1 
                    elif(inputs_position[optional_role_id] == 'mitm'):
                         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.destructStatistics.mitm  += 1 
                    elif(inputs_position[optional_role_id] == 'side'):
                         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.destructStatistics.side  += 1 
                    else: 
                        pass
        
        else:
            pass

        return minNonAvailableCost

#returning malware_forcing_sN_cost because it's the min
    if (minNonAvailableCost > malware_forcing_sN_cost ):

        #increase one for nCodeInjectCostK
        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].nCodeInjectCostK += 1 
        #increase protBreakCost counter
        if(theft_bool[minRoleIdInjection]):
            #increase one for protBreakCost.theft
            if(inputs_position[minRoleIdInjection] == 'peer'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.theftStatistics.peer  += 1 
            elif(inputs_position[minRoleIdInjection] == 'mitm'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.theftStatistics.mitm  += 1 
            elif(inputs_position[minRoleIdInjection] == 'side'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.theftStatistics.side  += 1 
            else: 
                pass
        else:
            #increase one for protBreakCost.destruct
            if(inputs_position[minRoleIdInjection] == 'peer'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.destructStatistics.peer  += 1 
            elif(inputs_position[minRoleIdInjection] == 'mitm'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.destructStatistics.mitm  += 1 
            elif(inputs_position[minRoleIdInjection] == 'side'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdInjection].protBreakCostStatistics.destructStatistics.side  += 1 
            else: 
                pass

        return malware_forcing_sN_cost
    
#else returning minNonAvailableCost
    if(minNonAvailableCost == 0):
        #increase one for costZero
        if(mandatory_0):
             mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_0].costZero += 1
        if(optional_0):
            for optional_role_id in roleId_optional_0:
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].costZero += 1

    elif(minNonAvailableCost == tcost):
        #tcost means compromission_mandatory_role
        if(theft_bool[roleId_mandatory_tcost]):
            #increase one for protBreakCost.theft
            if(inputs_position[roleId_mandatory_tcost] == 'peer'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.theftStatistics.peer  += 1 
            elif(inputs_position[roleId_mandatory_tcost] == 'mitm'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.theftStatistics.mitm  += 1 
            elif(inputs_position[roleId_mandatory_tcost] == 'side'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.theftStatistics.side  += 1 
            else: 
                pass
        else:
            #increase one for protBreakCost.destruct 
            if(inputs_position[minRoleIdInjection] == 'peer'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.destructStatistics.peer  += 1 
            elif(inputs_position[minRoleIdInjection] == 'mitm'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.destructStatistics.mitm  += 1 
            elif(inputs_position[minRoleIdInjection] == 'side'):
                 mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[roleId_mandatory_tcost].protBreakCostStatistics.destructStatistics.side  += 1 
            else: 
                pass
        
    elif(minNonAvailableCost == bdCost):
        #bdcost means compromission_optional_roles
        for optional_role_id in roleId_optional_compromission:
            if(theft_bool[optional_role_id]):
                #increase one for protBreakCost.theft
                if(inputs_position[optional_role_id] == 'peer'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(inputs_position[optional_role_id] == 'mitm'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(inputs_position[optional_role_id] == 'side'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass
            else:
                #increase one for protBreakCost.destruct 
                if(inputs_position[optional_role_id] == 'peer'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.destructStatistics.peer  += 1 
                elif(inputs_position[optional_role_id] == 'mitm'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.destructStatistics.mitm  += 1 
                elif(inputs_position[optional_role_id] == 'side'):
                     mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[optional_role_id].protBreakCostStatistics.destructStatistics.side  += 1 
                else: 
                    pass
    
    else:
        pass

    return minNonAvailableCost


def t2FtoB( mySystem, node ):

    NbInputs = len(node.inputs)
    NbRoles = len(node.roles)

    injection_inputs_position = [None]*NbRoles

    protocol_breaking_cost = [None]*NbRoles
    minTotalCost = [None]*NbRoles

    minmum_cost = None
    minRoleId = None
    
    if node.nodeType == 'kernel':
        return None
    
    if NbInputs <= 0:
        return None
    
    for i in range(NbInputs):
        if openFormula(mySystem, node.inputs[i] ):
            #if the input is in malware state or if it's in bad data state but in peer position
            if (mySystem.nodesStates[node.inputs[i].sourceNodeIndex] == 'sM' 
                or (mySystem.nodesStates[node.inputs[i].sourceNodeIndex]  == 'sB' 
                    and node.inputs[i].position == 'peer')):
                
                roleId = node.inputs[i].roleIndex
                attack_position = node.inputs[i].position
                attackerState = mySystem.nodesStates[node.inputs[i].sourceNodeIndex] 
                inputIndexInSystem = node.inputs[i].sourceNodeIndex

                protocol_breaking_cost[roleId] = ProtProtectCost(mySystem, node, i, roleId,  inputIndexInSystem, attack_position, attackerState)
                
                if protocol_breaking_cost[roleId] != None :
                    if node.roles[roleId].bCodeInjectCost != None:
                        minTotalCost[roleId] = protocol_breaking_cost[roleId] + node.roles[roleId].bCodeInjectCost

                injection_inputs_position[roleId]= attack_position

    minmum_cost = minNoneList(minTotalCost)[0]
    minRoleIdBDInjection = minNoneList(minTotalCost)[1]



    # If cost is still None, return None
    if minmum_cost == None:
        malware_forcing_sB_cost = None
    else:     
        malware_forcing_sB_cost = minmum_cost
        if(malware_forcing_sB_cost > maxCosts ):
            malware_forcing_sB_cost = None




    '''^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^^'''
    '''||||||||||||||||||||||||||||||||||||||||'''

    '''END OF CONDITION 3 MALWARE INJECTION FORCING BAD DATA STATUS '''

    rolCostBd = [None] * NbRoles
    rolOk = [False] * NbRoles #true if a role can stay OK thanks to legitimate producers

    bdCost = 0
    tcost=None

    compromissions_cost_mandatory = [None] * NbRoles

    totRolOK = 0
    totRolBd = 0
    mustcopromise = None
    nbCompr = 0
    activityCost = 0

    activityCost_mustcopromise_bool = False
    activityCost_bdcost_bool = False
    activityCost_tcost_bool = False


    protBreak_inputs_position = [None] * NbRoles

    tr1 = None
    j = None


    for i in range(NbRoles):
        rolOk[i] = True

    for i in range(NbInputs):
        rolOk[node.inputs[i].roleIndex] = False

    '''Processing Inputs: Analyzes the system's inputs to identify potential attackers and their 
    associated costs for producing bad data. 
     considers factors like the state of the attacker and the position of the attack.'''
    # for all no system inputs: 
    # we memorise potentiel B et M available attacker nodes and costs of B data submissions, B cost in composed from two values, session breaking and acceptable bad data generation, sum of Ok Weight 
    # first round, minimal costs  for available partners 
    for i in range(NbInputs):
        if openFormula(mySystem, node.inputs[i] ) and (node.roles[node.inputs[i].roleIndex].type != "system") and ( node.roles[node.inputs[i].roleIndex].categ != "transparent") :
            # // available inputs,  not pointing on system type roles and important roles only (mandatory & optional)
            '''input state'''
            attakernelerState = mySystem.nodesStates[node.inputs[i].sourceNodeIndex] 
            '''input position'''
            attakernel_position = node.inputs[i].position
            roleId = node.inputs[i].roleIndex
            inputIndexInSystem = node.inputs[i].sourceNodeIndex

            # costDir : cost of creation of acceptable data by role 
            dataBreakCost = node.roles[roleId].dataBreakCost
            
            # protCost : cost of protocol break                      
            protCost = ProtProtectCost(mySystem,node, i, roleId ,inputIndexInSystem, attakernel_position, attakernelerState)
            
            totalBreak = None 

            if protCost != None and dataBreakCost != None:
                totalBreak = dataBreakCost + protCost

            #prendre le minimum cost
            if totalBreak != None and (attakernelerState == "sM" or (attakernelerState == "sB" and attakernel_position == "peer")):
                if rolCostBd[roleId] == None or rolCostBd[roleId] > totalBreak:
                    rolCostBd[roleId] = totalBreak 
            #looking for the minimal cost of roles !!!!!!!!!!!!!!!!

            if attakernelerState == "sF" and attakernel_position == "peer":
                rolOk[roleId] = True 
                #keeping the roles that the inputs pointing on them are functional and in a peer position
            #keeping the inputs positions
            protBreak_inputs_position[roleId] = attakernel_position

    

    mandatory_role_idS_compromise_list = []

    for aroleid in range(NbRoles):
        if node.roles[aroleid].type != "system":
            if node.roles[aroleid].categ == "mandatory":
                if rolCostBd[aroleid] == None and  rolOk[aroleid] == False:
                    minbadDataCost = None 
                    #impossible to compromise not active mandatory role
                
                if rolOk[aroleid]== False:
                    # cost of compromission of all manadatrory and not OK roles
                    if mustcopromise != None:
                        mustcopromise = mustcopromise + rolCostBd[aroleid]
                        mandatory_role_idS_compromise_list.append(aroleid)

                    else:
                        mustcopromise = rolCostBd[aroleid]
                        mandatory_role_idS_compromise_list.append(aroleid)

                    '''always take the min'''
                if rolCostBd[aroleid] != None : #rolOk[aroleid]== True

                    if tcost == None or rolCostBd[aroleid] < tcost:
                        tcost = rolCostBd[aroleid] 
                        mandatory_role_id_compromise = aroleid

                    #minimal cost of  the compromissions of one of the mandatory role => tcost 

            elif node.roles[aroleid].categ == "optional" and rolOk[aroleid]:
                totRolOK += 1 
                # Nonember of OK optionnal roles
                '''ok roles means active roles or role can stay unaffected or secure against potential attacks'''
        compromissions_cost_mandatory[aroleid] = tcost
    
        
    min_mandatory_cost = minNoneList(compromissions_cost_mandatory)[0]
    min_mandatory_role_id =  minNoneList(compromissions_cost_mandatory)[1]


    ''' verify if the system has enough active roles to meet its required activity threshold'''

    if mustcopromise != None and totRolOK >= node.actThreshold  :
        minbadDataCost = mustcopromise #cost of compromissions of one of the mandatory

    else:#mustcopromise == None or totRolOK < node.actThreshold  

        #mustcopromise= sum rolCostBd[arole] = tt = costDir + protCost for each role

        #at this stage we know that we didn't return so  totRolOK  < node.actThreshold
        #Nonember of active roles wasn't enough
        nbCompr = node.actThreshold - totRolOK  #how many more active roles i need ?

        '''      // adding necessary non active optional roles for minimal activity'''
        listj = []
        for k in range(NbRoles):
            if nbCompr > 0:
                tr1 = None
                for aroleid in range(NbRoles):
                    
                    if ((node.roles[aroleid].type != "system") 
                        and (node.roles[aroleid].categ == "optional") 
                        and (rolCostBd[aroleid] != None) 
                        and rolOk[aroleid]== False):

                        if tr1 == None or tr1 > rolCostBd[aroleid]:
                            tr1 = rolCostBd[aroleid]
                            j = aroleid

                if tr1 != None:
                    nbCompr -= 1 
                    totRolBd += 1 #adding roles to  meet the activity threshold
                    activityCost += tr1 #adding the cost of compromizing this additionnal roles 
                    rolCostBd[j] = None
                    totRolOK += 1
            if(j != None):
                listj.append(j)
                        
            

        if nbCompr > 0 :
            minbadDataCost = None # impossible to have enough active optional roles

        else:
            if mustcopromise != None: #totRolOK < node.actThreshold 
                minbadDataCost = activityCost + mustcopromise 
                activityCost_mustcopromise_bool = True
                # // no necessary to add supplementary optionnal role to achieve plausThreshold
            
            else:
                '''• there is a subset of I of bad plausible data interpretations 
                pointing to a set R' of optional roles such that |R'| ≥ threshB, or
                '''
                # // adding necessary active optional roles for input bad data
                nbCompr = node.plausThreshold - totRolBd
                bdCost = None

                ''' Calculates the cost of compromising additional optional roles specifically for producing bad data. 
                This includes ensuring that compromising these roles doesn't exceed the system's capability.'''
                listk = []
                for aroleid in range(NbRoles): 
                    if nbCompr > 0: # for OK role only
                        tr1 = None
                        for aroleid in range(NbRoles):
                            if (node.roles[aroleid].type != "system") and (node.roles[aroleid].categ == "optional") and (
                                    rolCostBd[aroleid] != None) and rolOk[aroleid] == True:
                                
                                if tr1 == None or tr1 > rolCostBd[aroleid]:
                                    tr1 = rolCostBd[aroleid]
                                    j = aroleid

                        if tr1 != None:
                            nbCompr -= 1
                            if bdCost != None:
                                bdCost += tr1
                            else:
                                bdCost = tr1
                            rolCostBd[j] = None
                    if(j!= None):
                        listk.append(j)


               


                if nbCompr > 0 and tcost == None:
                    minbadDataCost = None
                else:
                    if tcost == None :
                        if bdCost == None:
                            minbadDataCost = activityCost
                        else:
                            minbadDataCost = activityCost + bdCost
                    else:
                        if bdCost != None:
                            if(tcost < bdCost):
                                minbadDataCost = activityCost + tcost 
                            else:
                                minbadDataCost = activityCost +  bdCost
                                activityCost_bdcost_bool = True

                        if(tcost != None and bdCost == None):
                            minbadDataCost = activityCost + tcost
                            activityCost_tcost_bool = True

    if(minbadDataCost == None  ):
        #increase one for bCodeInjectCostK
        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdBDInjection].bCodeInjectCostK += 1 

        
        #increase one for protBreakCost.theft
        if(injection_inputs_position[minRoleIdBDInjection] == 'peer'):
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdBDInjection].protBreakCostStatistics.theftStatistics.peer  += 1 
        elif(injection_inputs_position[minRoleIdBDInjection] == 'mitm'):
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdBDInjection].protBreakCostStatistics.theftStatistics.mitm  += 1 
        elif(injection_inputs_position[minRoleIdBDInjection] == 'side'):
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdBDInjection].protBreakCostStatistics.theftStatistics.side  += 1 
        else: 
            pass
        
        
        return malware_forcing_sB_cost

    if (malware_forcing_sB_cost == None) :
        #minbadDataCost = activityCost
        #minbadDataCost = activityCost + bdCost
        #minbadDataCost = activityCost + tCost
        #minbadDataCost = activityCost + mustcopromise
        #minbadDataCost = mustcopromise
        if(mustcopromise != None and minbadDataCost == mustcopromise):
            '''case of all mandatory roles comprmizing'''
            for man_role_id in mandatory_role_idS_compromise_list:
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].dataBreakCostK += 1 
                #increase one for protBreakCost.theft
                if(protBreak_inputs_position[man_role_id] == 'peer'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(protBreak_inputs_position[man_role_id] == 'mitm'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(protBreak_inputs_position[man_role_id] == 'side'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass
            

        elif(activityCost != None and mustcopromise != None and minbadDataCost == activityCost + mustcopromise):
            if(activityCost_mustcopromise_bool):
                '''case of one mandatory role comprmizing'''
                for man_role_id in mandatory_role_idS_compromise_list:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[man_role_id] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[man_role_id] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[man_role_id] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass
                '''case of one optional role need to be active'''
                for j in listj:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[j] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[j] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[j] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass

            
        elif(activityCost != None and minbadDataCost == activityCost):

            for j in listj:
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                #increase one for protBreakCost.theft
                if(protBreak_inputs_position[j] == 'peer'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(protBreak_inputs_position[j] == 'mitm'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(protBreak_inputs_position[j] == 'side'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass

        elif(activityCost != None and bdCost != None and minbadDataCost == activityCost + bdCost):
            if(activityCost_bdcost_bool):
                #bdcost
                for j in listk:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[j] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[j] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[j] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass


                for j in listj:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[j] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[j] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[j] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass

        elif(activityCost != None and tcost != None and minbadDataCost == activityCost + tcost):
            if(activityCost_tcost_bool):
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[mandatory_role_id_compromise].dataBreakCostK += 1 
                #increase one for protBreakCost.theft
                if(protBreak_inputs_position[mandatory_role_id_compromise] == 'peer'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[mandatory_role_id_compromise].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(protBreak_inputs_position[mandatory_role_id_compromise] == 'mitm'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[mandatory_role_id_compromise].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(protBreak_inputs_position[mandatory_role_id_compromise] == 'side'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[mandatory_role_id_compromise].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass


            for j in listj:
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                #increase one for protBreakCost.theft
                if(protBreak_inputs_position[j] == 'peer'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(protBreak_inputs_position[j] == 'mitm'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(protBreak_inputs_position[j] == 'side'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass

        else: 
            pass

        return minbadDataCost
    
    if( minbadDataCost < malware_forcing_sB_cost):
        #minbadDataCost = activityCost
        #minbadDataCost = activityCost + bdCost
        #minbadDataCost = activityCost + tCost
        #minbadDataCost = activityCost + mustcopromise
        #minbadDataCost = mustcopromise
        if(mustcopromise != None and minbadDataCost == mustcopromise):
            '''case of all mandatory roles comprmizing'''
            for man_role_id in mandatory_role_idS_compromise_list:
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].dataBreakCostK += 1 
                #increase one for protBreakCost.theft
                if(protBreak_inputs_position[man_role_id] == 'peer'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(protBreak_inputs_position[man_role_id] == 'mitm'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(protBreak_inputs_position[man_role_id] == 'side'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass
            

        elif(activityCost != None and mustcopromise != None and minbadDataCost == activityCost + mustcopromise):
            if(activityCost_mustcopromise_bool):
                '''case of one mandatory role comprmizing'''
                for man_role_id in mandatory_role_idS_compromise_list:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[man_role_id] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[man_role_id] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[man_role_id] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[man_role_id].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass
                '''case of one optional role need to be active'''
                for j in listj:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[j] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[j] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[j] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass

            
        elif(activityCost != None and minbadDataCost == activityCost):
            for j in listj:
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                #increase one for protBreakCost.theft
                if(protBreak_inputs_position[j] == 'peer'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(protBreak_inputs_position[j] == 'mitm'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(protBreak_inputs_position[j] == 'side'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass

        elif(activityCost != None and bdCost != None and minbadDataCost == activityCost + bdCost):
            if(activityCost_bdcost_bool):
                #bdcost
                for j in listk:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[j] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[j] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[j] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass


                for j in listj:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[j] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[j] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[j] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass

        elif(activityCost != None and tcost != None and minbadDataCost == activityCost + tcost):
            if(activityCost_tcost_bool):           
                mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[mandatory_role_id_compromise].dataBreakCostK += 1 
                #increase one for protBreakCost.theft
                if(protBreak_inputs_position[mandatory_role_id_compromise] == 'peer'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[mandatory_role_id_compromise].protBreakCostStatistics.theftStatistics.peer  += 1 
                elif(protBreak_inputs_position[mandatory_role_id_compromise] == 'mitm'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[mandatory_role_id_compromise].protBreakCostStatistics.theftStatistics.mitm  += 1 
                elif(protBreak_inputs_position[mandatory_role_id_compromise] == 'side'):
                        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[mandatory_role_id_compromise].protBreakCostStatistics.theftStatistics.side  += 1 
                else: 
                    pass


                for j in listj:
                    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].dataBreakCostK += 1 
                    #increase one for protBreakCost.theft
                    if(protBreak_inputs_position[j] == 'peer'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.peer  += 1 
                    elif(protBreak_inputs_position[j] == 'mitm'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.mitm  += 1 
                    elif(protBreak_inputs_position[j] == 'side'):
                            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[j].protBreakCostStatistics.theftStatistics.side  += 1 
                    else: 
                        pass

        else: 
            pass

        return minbadDataCost
    

    
    #increase one for bCodeInjectCostK
    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdBDInjection].bCodeInjectCostK += 1 

    
    #increase one for protBreakCost.theft
    if(injection_inputs_position[minRoleIdBDInjection] == 'peer'):
            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdBDInjection].protBreakCostStatistics.theftStatistics.peer  += 1 
    elif(injection_inputs_position[minRoleIdBDInjection] == 'mitm'):
            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdBDInjection].protBreakCostStatistics.theftStatistics.mitm  += 1 
    elif(injection_inputs_position[minRoleIdBDInjection] == 'side'):
            mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleIdBDInjection].protBreakCostStatistics.theftStatistics.side  += 1 
    else: 
        pass
    
    return malware_forcing_sB_cost


def t3FtoM(mySystem, node ):
    NbInputs = len(node.inputs)
    NbRoles = len(node.roles)
    inputs_position = [None]*NbInputs
    protocol_breaking_cost = [None]*NbRoles
    tcost = [None]*NbRoles
    minmum_cost = None
    
    if NbInputs <= 0:
        return None
    
    for i in range(NbInputs):
        if openFormula(mySystem, node.inputs[i] ):
            #if the input is in malware state or if it's in bad data state but in peer position
            if (mySystem.nodesStates[node.inputs[i].sourceNodeIndex] == 'sM' 
                or (mySystem.nodesStates[node.inputs[i].sourceNodeIndex]  == 'sB' and node.inputs[i].position == 'peer')):
                
                roleId = node.inputs[i].roleIndex
                attack_position = node.inputs[i].position
                attackerState = mySystem.nodesStates[node.inputs[i].sourceNodeIndex] 
                inputIndexInSystem = node.inputs[i].sourceNodeIndex

                protocol_breaking_cost[roleId] = ProtProtectCost(mySystem, node, i, roleId,  inputIndexInSystem, attack_position, attackerState)
                
                if protocol_breaking_cost[roleId] != None :

                    if  node.roles[roleId].mCodeInjectCost != None:
                        tcost[roleId] = protocol_breaking_cost[roleId] + node.roles[roleId].mCodeInjectCost
                        inputs_position[roleId]= [i , attack_position] 

                


    minmum_cost = minNoneList(tcost)[0]
    minRoleId =  minNoneList(tcost)[1]


    # If cost is still None, return None
    if minmum_cost == None:
        return None
    

    #increase one for mCodeInjectCostK
    mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleId].mCodeInjectCostK += 1 
    #increase one for protBreakCost.theft
    if(inputs_position[minRoleId] == 'peer'):
         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleId].protBreakCostStatistics.theftStatistics.peer  += 1 
    elif(inputs_position[minRoleId] == 'mitm'):
         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleId].protBreakCostStatistics.theftStatistics.mitm  += 1 
    elif(inputs_position[minRoleId] == 'side'):
         mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleId].protBreakCostStatistics.theftStatistics.side  += 1 
    else: 
        pass

    return minmum_cost


def t4FtoF(mySystem, node):
     
    NbInputs = len(node.inputs)
    NbRoles = len(node.roles)

    inputs_position = [None]*NbInputs

    protocol_breaking_cost = [None]*NbRoles
    tcost = [None]*NbRoles

    minmum_cost = None

    z = 0
    
    # Check if there are inputs
    if NbInputs <= 0:
        return None
    
    # Loop through each key
    for i in range(5):
        # Check if the secret is not already stolen and if it's stored locally

        if (not mySystem.stolenSecrets[i]) and mySystem.nodes[node.id].secrStore[i]:
            z += 1
    
    # If no secrets are found locally, return None
    if z == 0:
        return None
    
    # Loop through each input
    for inputindex in range(NbInputs):
        # Check if the input is openFormula and its state is 'sM'
        ''' malware on inputs try to steal all locally stored secrets '''
        if openFormula(mySystem, node.inputs[inputindex] ) and mySystem.nodesStates[node.inputs[inputindex].sourceNodeIndex] == 'sM':
            # Retrieve roleid, attack position, and attacker state
            roleId = node.inputs[inputindex].roleIndex
            attack_position = node.inputs[inputindex].position
            attackerState = mySystem.nodesStates[node.inputs[inputindex].sourceNodeIndex] 
            inputIndexInSystem = node.inputs[inputindex].sourceNodeIndex

            # Calculate protocol access cost
            protocol_breaking_cost[roleId] = ProtProtectCost(mySystem, node, inputindex, roleId, inputIndexInSystem , attack_position, attackerState)
            

            # Adjust cost based on role parameter
            if protocol_breaking_cost[roleId] != None and node.roles[roleId].remoteSecrTheftCost != None:
                tcost[roleId] = protocol_breaking_cost[roleId] + node.roles[roleId].remoteSecrTheftCost

                inputs_position[roleId]= attack_position
            else:
                tcost[roleId] = None
            
    minmum_cost = minNoneList(tcost)[0]
    minRoleId =  minNoneList(tcost)[1]


    # If cost is still None, return None
    if minmum_cost == None:
        return None
    
    
    # Check if the total cost is within the maximum allowed costs
    if (minmum_cost ) <= maxCosts:
        #increase one for remoteSecrTheftCost
        mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleId].remoteSecrTheftCostK  += 1 
        #increase one for protBreakCost.theft
        if(inputs_position[minRoleId] == 'peer'):
             mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleId].protBreakCostStatistics.theftStatistics.peer  += 1 
        elif(inputs_position[minRoleId] == 'mitm'):
             mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleId].protBreakCostStatistics.theftStatistics.mitm  += 1 
        elif(inputs_position[minRoleId] == 'side'):
             mySystem.resultStructure[node.id].nodeStatistics.roleStatistics[minRoleId].protBreakCostStatistics.theftStatistics.side  += 1 
        else: 
            pass

        return minmum_cost
    else:
        return None


def t5MtoM(mySystem, node):
    for i in range(5):
        if (( mySystem.stolenSecrets[i]) == False and mySystem.nodes[node.id].secrStore[i] == True ):
            cost=node.secrTheftCost
            if ((cost)<=maxCosts):

                # cumulation with one "1" or saving the cost=node.secrTheftCost
                mySystem.resultStructure[node.id].nodeStatistics.secrTheftCostK += 1 
                
                return cost
            return None
    return None





