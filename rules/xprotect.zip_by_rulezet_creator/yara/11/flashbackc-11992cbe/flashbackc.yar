import "hash"
rule FlashbackC
{
    meta:
        description = "OSX.Flashback.C"
        xprotect_rule = true
    condition:
        filesize <= 300000 and (
            hash.sha1(0, filesize) == "12f814ef8258caa2b84bf763af8333e738b5df76" or
            hash.sha1(0, filesize) == "131db26684cfa17a675f5ff9a67a82ce2864ac95" or
            hash.sha1(0, filesize) == "140fba4cafa2a3dff128c5cceeb12ce3e846fa2b" or
            hash.sha1(0, filesize) == "585e1e8aa48680ba2c4c159c6a422f05a5ca1e5c" or
            hash.sha1(0, filesize) == "392b6b110cec1960046061d37ca0368d1c769c65" or
            hash.sha1(0, filesize) == "b95a2a9a15a67c1f4dfce1f3ee8ef4429f86747c"
        )
}