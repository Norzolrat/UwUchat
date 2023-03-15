# Installation

``` 
python -m pip install -r requirements.txt
```

# Utilisation

`./server.py` : lance le serveur (port 80)
`./client.py` : lance le client (se connecte sur http://127.0.0.1)

La BDD du serveur n'est pas enregistrée (dict en mémoire), donc il se reset à chaque fois ...


# Objectifs :

Dans le fichier mycrypto.py se trouvent toutes les primitives crypto qui seront utiles
(AES, RSA, Hash) ... Normalement il y a tout :)

Il faut :
1 / changer le stockage des mots de passes, actuellement en clairs dans la "BDD"
2 / Chiffrer le canal entre client et serveur (attaquant 1)

Les endroits à changer sont les "#TODO" dans le code


# Petites infos techniques :

Le client va envoyer un JSON au serveur en POST
Ce JSON va contenir la clé AES chiffrée, l'IV, et le message chiffré en AES.

Ce message sera lui même du JSON :
côté client on donne à la fonction send_request un dict, et on le récupère dans la fonction handle_request du serveur.
Au milieu : il va falloir le chiffrer ....