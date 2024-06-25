def isOpen(isOpen, nodesNames, nodesStates):
    replayced = isOpen.replace('$', 's')
    splited = replayced.split('&')
    splited2 = []
    for value in splited:
        splited2.append( value.split('<>')[0].replace(" ",""))
    indexs = []
    for value in splited2:
        indexs.append(nodesNames.index(value))
    for i in indexs:
        if nodesStates[i] == 'sN':
            return False
    return True
