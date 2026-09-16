rule libprocesshider
{
    meta:
        description = "Detection patterns for the tool 'libprocesshider' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "libprocesshider"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sevil_script\.py/
                        $string2 = /\slibprocesshider\.so\s/
                        $string3 = "/bin/processhider"
                        $string4 = /\/evil_script\.py/
                        $string5 = /\/libprocesshider\.git/
                        $string6 = /\/libprocesshider\.so/
                        $string7 = /\/processhider\.c/
                        $string8 = /\\evil_script\.py/
                        $string9 = "16d765e024adacabe84e9fd889030f5481546ef711bba0043e7e84eadd257d1a"
                        $string10 = "eb5fee1e402f321c8e705776faf2be7bbede5d2a24fe3ac40be082a75429f927"
                        $string11 = "gianlucaborello/libprocesshider"
                        $string12 = /https\:\/\/sysdig\.com\/blog\/hiding\-linux\-processes\-for\-fun\-and\-profit\//
                        $string13 = /sock\.send\(\\"\\"I\sAM\sA\sBAD\sBOY\\"\\"\)/

    condition:
        any of them
}