import "hash"
rule IWormBC
{
    meta:
        description = "OSX.iWorm.B/C"
        xprotect_rule = true
    condition:
        filesize <= 500 and hash.sha1(0, filesize) == "5e68569d32772a479dfa9e6a23b2f3ae74b2028f"
        
}