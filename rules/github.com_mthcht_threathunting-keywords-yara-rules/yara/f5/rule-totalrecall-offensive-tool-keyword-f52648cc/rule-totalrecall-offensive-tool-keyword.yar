rule rule_TotalRecall_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'TotalRecall' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TotalRecall"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_TotalRecall_offensive_tool_keyword = " Recall folder found: " nocase ascii wide
                        $string2_TotalRecall_offensive_tool_keyword = /\s\-\-search\spassword\s\-\-from_date\s.{0,1000}\s\-\-to_date\s/ nocase ascii wide
                        $string3_TotalRecall_offensive_tool_keyword = /\stotalrecall\.py/ nocase ascii wide
                        $string4_TotalRecall_offensive_tool_keyword = /\sWindows\sRecall\sfeature\sfound\.\sDo\syou\swant\sto\sproceed\swith\sthe\sextraction\?/ nocase ascii wide
                        $string5_TotalRecall_offensive_tool_keyword = /\sWindows\sRecall\sfeature\snot\sfound\.\sNothing\sto\sextract/ nocase ascii wide
                        $string6_TotalRecall_offensive_tool_keyword = /\/TotalRecall\.git/ nocase ascii wide
                        $string7_TotalRecall_offensive_tool_keyword = /\/totalrecall\.py/ nocase ascii wide
                        $string8_TotalRecall_offensive_tool_keyword = /\/TotalRecall\.txt/
                        $string9_TotalRecall_offensive_tool_keyword = /\\2024\-.{0,1000}_Recall_Extraction\\/ nocase ascii wide
                        $string10_TotalRecall_offensive_tool_keyword = /\\2025\-.{0,1000}_Recall_Extraction\\/ nocase ascii wide
                        $string11_TotalRecall_offensive_tool_keyword = /\\totalrecall\.py/ nocase ascii wide
                        $string12_TotalRecall_offensive_tool_keyword = /\\TotalRecall\.txt/ nocase ascii wide
                        $string13_TotalRecall_offensive_tool_keyword = /\\TotalRecall\\.{0,1000}_Recall_Extraction/ nocase ascii wide
                        $string14_TotalRecall_offensive_tool_keyword = "353f18e314f024ceea013bd97c140e09fd4ac715bf9ac7c965d0b89845dffcf0" nocase ascii wide
                        $string15_TotalRecall_offensive_tool_keyword = /C\:\\\\Users\\\\\{username\}\\\\AppData\\\\Local\\\\CoreAIPlatform\.00\\\\UKP/ nocase ascii wide
                        $string16_TotalRecall_offensive_tool_keyword = /extraction_folder.{0,1000}TotalRecall\.txt/ nocase ascii wide
                        $string17_TotalRecall_offensive_tool_keyword = /SELECT\sWindowTitle\,\sTimeStamp\,\sImageToken\s.{0,1000}FROM\sWindowCapture/ nocase ascii wide
                        $string18_TotalRecall_offensive_tool_keyword = "xaitax/TotalRecall" nocase ascii wide

    condition:
        any of them
}