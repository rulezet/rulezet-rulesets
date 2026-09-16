rule rule_telebit_cloud_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'telebit.cloud' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "telebit.cloud"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_telebit_cloud_greyware_tool_keyword = /\.config\/telebit\/telebitd\.yml/ nocase ascii wide
                        $string2_telebit_cloud_greyware_tool_keyword = /\/cloud\.telebit\.remote\.plist/
                        $string3_telebit_cloud_greyware_tool_keyword = "/opt/telebit"
                        $string4_telebit_cloud_greyware_tool_keyword = "/telebit http "
                        $string5_telebit_cloud_greyware_tool_keyword = /\/telebit\.js\.git/
                        $string6_telebit_cloud_greyware_tool_keyword = /\/telebit\.service/
                        $string7_telebit_cloud_greyware_tool_keyword = "/telebit/var/log/"
                        $string8_telebit_cloud_greyware_tool_keyword = /\/telebit\-remote\.js/
                        $string9_telebit_cloud_greyware_tool_keyword = /bin\/telebit\.js/ nocase ascii wide
                        $string10_telebit_cloud_greyware_tool_keyword = /cloud\.telebit\.remot/ nocase ascii wide
                        $string11_telebit_cloud_greyware_tool_keyword = /https\:\/\/.{0,1000}\.telebit\.io/ nocase ascii wide
                        $string12_telebit_cloud_greyware_tool_keyword = /https\:\/\/get\.telebit\.io/ nocase ascii wide
                        $string13_telebit_cloud_greyware_tool_keyword = "install -g telebit" nocase ascii wide
                        $string14_telebit_cloud_greyware_tool_keyword = /netcat\s.{0,1000}\.telebit\.io/ nocase ascii wide
                        $string15_telebit_cloud_greyware_tool_keyword = /ssh\s\-o\s.{0,1000}\.telebit\.io/ nocase ascii wide
                        $string16_telebit_cloud_greyware_tool_keyword = /ssh.{0,1000}\.telebit\.cloud/ nocase ascii wide
                        $string17_telebit_cloud_greyware_tool_keyword = "telebit ssh auto" nocase ascii wide
                        $string18_telebit_cloud_greyware_tool_keyword = "telebit tcp " nocase ascii wide
                        $string19_telebit_cloud_greyware_tool_keyword = "--user-unit=telebit" nocase ascii wide

    condition:
        any of them
}