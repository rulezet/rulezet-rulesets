rule Shellcode_Downloader_CreateThread_Execution
{
    meta:
        description = "Detection patterns for the tool 'Shellcode-Downloader-CreateThread-Execution' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Shellcode-Downloader-CreateThread-Execution"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = "Shellcode-Download_CreateThread_Execution" nocase ascii wide
                        $string2 = "Shellcode-Downloader-CreateThread-Execution" nocase ascii wide

    condition:
        any of them
}