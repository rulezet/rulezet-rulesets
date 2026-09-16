rule rule_cloudsploit_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'cloudsploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloudsploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_cloudsploit_offensive_tool_keyword = " cloudsploit" nocase ascii wide
                        $string2_cloudsploit_offensive_tool_keyword = "/aquasecurity/cloudsploit" nocase ascii wide
                        $string3_cloudsploit_offensive_tool_keyword = /\/cloudsploit\.git/ nocase ascii wide
                        $string4_cloudsploit_offensive_tool_keyword = "cloudsploit " nocase ascii wide
                        $string5_cloudsploit_offensive_tool_keyword = /cloudsploit.{0,1000}cloudtrail/ nocase ascii wide
                        $string6_cloudsploit_offensive_tool_keyword = /cloudsploit\/index\.js/ nocase ascii wide
                        $string7_cloudsploit_offensive_tool_keyword = "cloudsploit/scans" nocase ascii wide
                        $string8_cloudsploit_offensive_tool_keyword = "CloudSploitSupplemental" nocase ascii wide

    condition:
        any of them
}