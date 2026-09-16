rule rule_mediafire_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'mediafire' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "mediafire"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_mediafire_greyware_tool_keyword = /\/download.{0,1000}mediafire\.com\// nocase ascii wide
                        $string2_mediafire_greyware_tool_keyword = /https\:\/\/www\.mediafire\.com\/api\/.{0,1000}\/folder\/get_content\.php/ nocase ascii wide
                        $string3_mediafire_greyware_tool_keyword = /www\.mediafire\.com\/api\/1\.5\/upload\// nocase ascii wide
                        $string4_mediafire_greyware_tool_keyword = /www\.mediafire\.com\/file\// nocase ascii wide
                        $string5_mediafire_greyware_tool_keyword = /www\.mediafire\.com\/file\/.{0,1000}\.rar\/file/ nocase ascii wide
                        $string6_mediafire_greyware_tool_keyword = /www\.mediafireuserupload\.com\/api\/upload\// nocase ascii wide

    condition:
        any of them
}