rule TotalRecall
{
    meta:
        description = "Detection patterns for the tool 'TotalRecall' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "TotalRecall"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " Recall folder found: " nocase ascii wide
                        $string2 = /\s\-\-search\spassword\s\-\-from_date\s.{0,1000}\s\-\-to_date\s/ nocase ascii wide
                        $string3 = /\stotalrecall\.py/ nocase ascii wide
                        $string4 = /\sWindows\sRecall\sfeature\sfound\.\sDo\syou\swant\sto\sproceed\swith\sthe\sextraction\?/ nocase ascii wide
                        $string5 = /\sWindows\sRecall\sfeature\snot\sfound\.\sNothing\sto\sextract/ nocase ascii wide
                        $string6 = /\/TotalRecall\.git/ nocase ascii wide
                        $string7 = /\/totalrecall\.py/ nocase ascii wide
                        $string8 = /\/TotalRecall\.txt/
                        $string9 = /\\2024\-.{0,1000}_Recall_Extraction\\/ nocase ascii wide
                        $string10 = /\\2025\-.{0,1000}_Recall_Extraction\\/ nocase ascii wide
                        $string11 = /\\totalrecall\.py/ nocase ascii wide
                        $string12 = /\\TotalRecall\.txt/ nocase ascii wide
                        $string13 = /\\TotalRecall\\.{0,1000}_Recall_Extraction/ nocase ascii wide
                        $string14 = "353f18e314f024ceea013bd97c140e09fd4ac715bf9ac7c965d0b89845dffcf0" nocase ascii wide
                        $string15 = /C\:\\\\Users\\\\\{username\}\\\\AppData\\\\Local\\\\CoreAIPlatform\.00\\\\UKP/ nocase ascii wide
                        $string16 = /extraction_folder.{0,1000}TotalRecall\.txt/ nocase ascii wide
                        $string17 = /SELECT\sWindowTitle\,\sTimeStamp\,\sImageToken\s.{0,1000}FROM\sWindowCapture/ nocase ascii wide
                        $string18 = "xaitax/TotalRecall" nocase ascii wide

    condition:
        any of them
}