rule cloudsploit
{
    meta:
        description = "Detection patterns for the tool 'cloudsploit' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "cloudsploit"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " cloudsploit" nocase ascii wide
                        $string2 = "/aquasecurity/cloudsploit" nocase ascii wide
                        $string3 = /\/cloudsploit\.git/ nocase ascii wide
                        $string4 = "cloudsploit " nocase ascii wide
                        $string5 = /cloudsploit.{0,1000}cloudtrail/ nocase ascii wide
                        $string6 = /cloudsploit\/index\.js/ nocase ascii wide
                        $string7 = "cloudsploit/scans" nocase ascii wide
                        $string8 = "CloudSploitSupplemental" nocase ascii wide

    condition:
        any of them
}