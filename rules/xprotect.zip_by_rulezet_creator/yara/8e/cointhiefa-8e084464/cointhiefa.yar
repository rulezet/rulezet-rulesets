import "hash"
rule CoinThiefA
{
    meta:
        description = "OSX.CoinThief.A"
        xprotect_rule = true
    condition:
        filesize <= 350000 and (
        	hash.sha1(0, filesize) == "37c4bc94f2c08e90a47825fe7b2afbce908b5d74"
        )
}