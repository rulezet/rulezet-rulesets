rule rule_Azure_Storage_Explorer_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'Azure Storage Explorer' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "Azure Storage Explorer"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_Azure_Storage_Explorer_greyware_tool_keyword = /\/Microsoft\sAzure\sStorage\sExplorer\.app/ nocase ascii wide
                        $string2_Azure_Storage_Explorer_greyware_tool_keyword = /\/Microsoft\sAzure\sStorage\sExplorer\.zip/ nocase ascii wide
                        $string3_Azure_Storage_Explorer_greyware_tool_keyword = /\\Microsoft\sAzure\sStorage\sExplorer\.zip/ nocase ascii wide
                        $string4_Azure_Storage_Explorer_greyware_tool_keyword = ">Microsoft Azure Storage Explorer Setup<" nocase ascii wide
                        $string5_Azure_Storage_Explorer_greyware_tool_keyword = ">Microsoft Azure Storage Explorer<" nocase ascii wide
                        $string6_Azure_Storage_Explorer_greyware_tool_keyword = "036a9029e3b883ded8de9d9bdde3f63dd86d3403b7ed767b1efc3037c9d37bc4" nocase ascii wide
                        $string7_Azure_Storage_Explorer_greyware_tool_keyword = "7fa49a08d05a3616b5a24f52645d76c4496c37f5060a6bd4a648f534c4e85ae0" nocase ascii wide
                        $string8_Azure_Storage_Explorer_greyware_tool_keyword = "c798b2aedc7a74f0daf51eb216aae8cb48b45f208b0409916442b1d61d2ad2ef" nocase ascii wide
                        $string9_Azure_Storage_Explorer_greyware_tool_keyword = /com\.microsoft\.StorageExplorer/ nocase ascii wide
                        $string10_Azure_Storage_Explorer_greyware_tool_keyword = /Microsoft\sAzure\sStorage\sExplorer\.app\/Contents\// nocase ascii wide
                        $string11_Azure_Storage_Explorer_greyware_tool_keyword = /StorageExplorer\-linux\-x64\.tar\.gz/
                        $string12_Azure_Storage_Explorer_greyware_tool_keyword = /StorageExplorer\-windows\-x64\.exe/ nocase ascii wide

    condition:
        any of them
}