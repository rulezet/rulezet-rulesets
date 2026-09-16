import "hash"
rule AdPluginB
{
    meta:
        description = "OSX.AdPlugin2.i"
        xprotect_rule = true
    condition:
        filesize <= 40000 and hash.sha1(0, filesize) == "fe59a309e5689374dba50bc7349d62148f1ab9aa"
}