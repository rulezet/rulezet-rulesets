rule rule_DCOMUploadExec_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'DCOMUploadExec' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "DCOMUploadExec"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_DCOMUploadExec_offensive_tool_keyword = /\/DCOMUploadExec\.exe/ nocase ascii wide
                        $string2_DCOMUploadExec_offensive_tool_keyword = /\/DCOMUploadExec\.git/ nocase ascii wide
                        $string3_DCOMUploadExec_offensive_tool_keyword = /\[\+\]\sCreated\sa\sremote\sGAC\sfile\sstream/ nocase ascii wide
                        $string4_DCOMUploadExec_offensive_tool_keyword = /\\DCOMUploadExec\.exe/ nocase ascii wide
                        $string5_DCOMUploadExec_offensive_tool_keyword = /\\DCOMUploadExec\.sln/ nocase ascii wide
                        $string6_DCOMUploadExec_offensive_tool_keyword = /\\DCOMUploadExec\-main/ nocase ascii wide
                        $string7_DCOMUploadExec_offensive_tool_keyword = "57FD94EC-4361-43FD-AB9D-CDB254C0DE8F" nocase ascii wide
                        $string8_DCOMUploadExec_offensive_tool_keyword = "781a54a1bb3fb0960ce374f79a50ba0870e824a5b2432ee8cb2de3b5b8883128" nocase ascii wide
                        $string9_DCOMUploadExec_offensive_tool_keyword = "7bf6b6be-a29f-440a-9962-9fabc5d9665a" nocase ascii wide
                        $string10_DCOMUploadExec_offensive_tool_keyword = /ASSEMBLY_PUBLIC_KEY.{0,1000}136e5fbf23bb401e/ nocase ascii wide
                        $string11_DCOMUploadExec_offensive_tool_keyword = "c4d95bff1eced83e423deb8555d636b02c290adba785a349bc776711bbc2841e" nocase ascii wide
                        $string12_DCOMUploadExec_offensive_tool_keyword = /DCOMUploadExec\.exe\s/ nocase ascii wide
                        $string13_DCOMUploadExec_offensive_tool_keyword = /DCOMUploadExec\-main\.zip/ nocase ascii wide
                        $string14_DCOMUploadExec_offensive_tool_keyword = "deepinstinct/DCOMUploadExec" nocase ascii wide
                        $string15_DCOMUploadExec_offensive_tool_keyword = "MSIEXEC - GAC backdoor installed" nocase ascii wide

    condition:
        any of them
}