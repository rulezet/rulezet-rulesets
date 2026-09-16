rule usaupload
{
    meta:
        description = "Detection patterns for the tool 'usaupload' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "usaupload"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /https\:\/\/usaupload\.com\/account\/ajax\/load_files/ nocase ascii wide
                        $string2 = /https\:\/\/usaupload\.com\/account\/ajax\/uploader/ nocase ascii wide

    condition:
        any of them
}