rule APT1_WEBC2_Y21K
{

    meta:
        author = "AlienVault Labs"
        info = "CommentCrew-threat-apt1"
        
    strings:
        $1 = "Y29ubmVjdA" wide ascii         $2 = "c2xlZXA" wide ascii         $3 = "cXVpdA" wide ascii         $4 = "Y21k" wide ascii         $5 = "dW5zdXBwb3J0" wide ascii 
    condition:
        4 of them
}