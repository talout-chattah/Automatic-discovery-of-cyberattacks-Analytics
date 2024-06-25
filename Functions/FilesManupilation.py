from modules.step import step
import os
import hashlib
def extractTrace(uppalTracePath,nbKeys, nbNodes):
    with open(uppalTracePath, 'r') as file:
        content = file.read().replace('\n', ' ')
        steps = content.split('. .')
    etapes = []
    for i in range(2,len(steps)-1):
        stepcontent = steps[i].split('.')
        stepcontent[0] = stepcontent[0].replace(' ','',nbKeys + nbNodes)
        keysAndNodes = stepcontent[0].split(' ')
        keys = []
        nodes = []
        for j in range(0,nbKeys):

            if(stepcontent[0][j] == '0'):
                keys.append(False)
            else:
                keys.append(True)

        for j in range(nbKeys, nbKeys + nbNodes):
            if(stepcontent[0][j] == '0'):
                nodes.append('sF')
            elif(stepcontent[0][j] == '1'):
                nodes.append('sM')
            elif(stepcontent[0][j] == '2'):
                nodes.append('sB')
            else:
                nodes.append('sN')

        etapes.append( step(keys, nodes, keysAndNodes[1], keysAndNodes[2]))
        
    return etapes

def extractConcretTrace(uppalTracePath,nbKeys, nbNodes):
    
    with open(uppalTracePath, 'r') as file:
        content = file.read()
        steps = content.split('\"state\":')
        etapes = []
        # key and nodes states and cost of the step and step number i starts from 1 to len(steps)
        for i in range(1, len(steps)):    
            etape = str(steps[i].split('\"vars\":')[1].split(',\"fpvars\"')[0]).replace('[','').replace(']','').split(',')
            keysStates = []
            nodesStates = []
            for j in range (0, nbKeys):
                    if(etape[j] == '0'):
                        keysStates.append(False)
                    else:
                        keysStates.append(True)
            for j in range(nbKeys, nbKeys + nbNodes):
                    if(etape[j] == '0'):
                        nodesStates.append('sF')
                    elif(etape[j] == '1'):
                        nodesStates.append('sM')
                    elif(etape[j] == '2'):
                        nodesStates.append('sB')
                    else:
                        nodesStates.append('sN')
            stepcost = etape[nbKeys + nbNodes]
            stepNumber = etape[nbKeys + nbNodes + 1]

            etapes.append( step(keysStates, nodesStates, stepcost, stepNumber, None))

        yousra = []
        for i in range(1, len(steps)-1):
            nextNode = str(steps[i].split('\"procnum\":')[1].split(',')[0])
            yousra.append(nextNode)
        
        for i in range(0, len(etapes)-1):
            etapes[i].nextNode = yousra[i] 
    return etapes

def hash_file(file_path):
    hasher = hashlib.sha256()
    with open(file_path, 'rb') as f:
        buf = f.read()
        hasher.update(buf)
    return hasher.hexdigest()

def find_and_remove_duplicates(directory):
    file_hashes = {}
    for root, _, files in os.walk(directory):
        for file in files:
            file_path = os.path.join(root, file)
            file_hash = hash_file(file_path)
            if file_hash in file_hashes:
                print(f"Suppression du fichier en double : {file_path}")
                os.remove(file_path)
            else:
                file_hashes[file_hash] = file_path