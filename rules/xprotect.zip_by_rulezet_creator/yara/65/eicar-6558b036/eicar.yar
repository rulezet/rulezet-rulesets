import "hash"
rule EICAR
{
    meta:
        description = "OSX.eicar.com.i"
        xprotect_rule = true
    condition:
        filesize <= 100000000 and hash.sha1(0, filesize) == "3395856ce81f2b7382dee72602f798b642f14140"
}