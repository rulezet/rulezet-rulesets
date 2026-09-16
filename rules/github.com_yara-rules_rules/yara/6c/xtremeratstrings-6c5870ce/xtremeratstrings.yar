rule XtremeRATStrings : XtremeRAT Family
{
    meta:
        description = "XtremeRAT Identifying Strings"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    strings:
        $ = "dqsaazere"
        $ = "-GCCLIBCYGMING-EH-TDM1-SJLJ-GTHR-MINGW32"
        
    condition:
        all of them
}