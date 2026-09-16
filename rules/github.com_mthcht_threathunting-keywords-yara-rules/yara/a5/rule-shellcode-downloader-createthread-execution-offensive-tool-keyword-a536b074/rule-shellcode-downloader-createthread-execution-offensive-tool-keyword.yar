rule rule_Shellcode_Downloader_CreateThread_Execution_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Shellcode-Downloader-CreateThread-Execution' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shellcode-Downloader-CreateThread-Execution"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_Shellcode_Downloader_CreateThread_Execution_offensive_tool_keyword = "Shellcode-Download_CreateThread_Execution" nocase ascii wide
                        $string2_Shellcode_Downloader_CreateThread_Execution_offensive_tool_keyword = "Shellcode-Downloader-CreateThread-Execution" nocase ascii wide

    condition:
        any of them
}