import "hash"
rule AdPluginA
{
    meta:
        description = "OSX.AdPlugin.i"
        xprotect_rule = true
    condition:
        filesize <= 500000 and hash.sha1(0, filesize) == "f63805148d85d8b757a50580bba11e02c192a2b8"
}