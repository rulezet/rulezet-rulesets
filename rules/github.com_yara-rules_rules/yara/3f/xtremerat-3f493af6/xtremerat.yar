rule XtremeRAT : Family
{
    meta:
        description = "XtremeRAT"
        author = "Seth Hardy"
        last_modified = "2014-07-09"
        
    condition:
        XtremeRATCode or XtremeRATStrings
}