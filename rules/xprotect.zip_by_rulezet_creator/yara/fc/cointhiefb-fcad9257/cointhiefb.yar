import "hash"
rule CoinThiefB
{
    meta:
        description = "OSX.CoinThief.B"
        xprotect_rule = true
    condition:
        filesize <= 3000000 and (
            hash.sha1(0, filesize) == "c2b81f705670c837c0bf5a2ddd1e398e967c0a08" or
            hash.sha1(0, filesize) == "02e243157dbc8803a364e9410a5c41b36de64c95" 
        )
}