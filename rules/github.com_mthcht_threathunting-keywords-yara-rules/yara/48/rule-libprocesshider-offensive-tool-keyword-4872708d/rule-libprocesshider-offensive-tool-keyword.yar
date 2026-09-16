rule rule_libprocesshider_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'libprocesshider' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "libprocesshider"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_libprocesshider_offensive_tool_keyword = /\sevil_script\.py/
                        $string2_libprocesshider_offensive_tool_keyword = /\slibprocesshider\.so\s/
                        $string3_libprocesshider_offensive_tool_keyword = "/bin/processhider"
                        $string4_libprocesshider_offensive_tool_keyword = /\/evil_script\.py/
                        $string5_libprocesshider_offensive_tool_keyword = /\/libprocesshider\.git/
                        $string6_libprocesshider_offensive_tool_keyword = /\/libprocesshider\.so/
                        $string7_libprocesshider_offensive_tool_keyword = /\/processhider\.c/
                        $string8_libprocesshider_offensive_tool_keyword = /\\evil_script\.py/
                        $string9_libprocesshider_offensive_tool_keyword = "16d765e024adacabe84e9fd889030f5481546ef711bba0043e7e84eadd257d1a"
                        $string10_libprocesshider_offensive_tool_keyword = "eb5fee1e402f321c8e705776faf2be7bbede5d2a24fe3ac40be082a75429f927"
                        $string11_libprocesshider_offensive_tool_keyword = "gianlucaborello/libprocesshider"
                        $string12_libprocesshider_offensive_tool_keyword = /https\:\/\/sysdig\.com\/blog\/hiding\-linux\-processes\-for\-fun\-and\-profit\//
                        $string13_libprocesshider_offensive_tool_keyword = /sock\.send\(\\"\\"I\sAM\sA\sBAD\sBOY\\"\\"\)/

    condition:
        any of them
}