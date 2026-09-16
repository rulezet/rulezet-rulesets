rule WarpStrings : Warp Family
{
    meta:
        description = "Warp Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-10"
        
    strings:
        $ = "/2011/n325423.shtml?"
        $ = "wyle"
        $ = "\\~ISUN32.EXE"

    condition:
       any of them
}