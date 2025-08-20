Here's the bat bones, 100% human generated:

When you find block N, you include in the block some cryptographic thing. Proof of a secret.  
When you find block N+1, you includ in the block proof that you know the secret from block N. 
Others (the protocol) can verify. You also include a new secret for the next block you find.
You have created a verifiable temporal chain of proof of these secrets, indicating that you have been mining for a while.  
This adds a new weight to be considered during a fork choice event.
When an attacker creates a private chain, they won't have this chain of proof.
The protocol will prefer blocks that have a chain of proof.
Mainly active during fork choice events / re-orgs. (when trying to add multiple blocks). 
Should not be active during single block entry. (permits miners without history to participate as normal)
Window needs to be long (n years). Mainly raises the bar, can not prevent an attacker thats willing to dedicate n years.
