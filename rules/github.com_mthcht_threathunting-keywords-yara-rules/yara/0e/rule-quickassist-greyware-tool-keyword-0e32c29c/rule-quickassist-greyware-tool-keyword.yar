rule rule_QuickAssist_greyware_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'QuickAssist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "QuickAssist"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1_QuickAssist_greyware_tool_keyword = /\s\-\-webview\-exe\-name\=QuickAssist\.exe/ nocase ascii wide
                        $string2_QuickAssist_greyware_tool_keyword = /\/Assistance\srapide\sInstaller\.exe/ nocase ascii wide
                        $string3_QuickAssist_greyware_tool_keyword = /\/Assistenza\srapida\sInstaller\.exe/ nocase ascii wide
                        $string4_QuickAssist_greyware_tool_keyword = /\/Quick\sAssist\sInstaller\.exe/ nocase ascii wide
                        $string5_QuickAssist_greyware_tool_keyword = /\/Quick\%20Assist\%20Installer\.exe/ nocase ascii wide
                        $string6_QuickAssist_greyware_tool_keyword = /\\AppData\\Local\\Temp\\RemoteHelp\\EBWebView/ nocase ascii wide
                        $string7_QuickAssist_greyware_tool_keyword = /\\Assistance\srapide\sInstaller\.exe/ nocase ascii wide
                        $string8_QuickAssist_greyware_tool_keyword = /\\Assistenza\srapida\sInstaller\.exe/ nocase ascii wide
                        $string9_QuickAssist_greyware_tool_keyword = /\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\.{0,1000}\\MicrosoftCorporationII\.QuickAssist_/ nocase ascii wide
                        $string10_QuickAssist_greyware_tool_keyword = /\\Microsoft\.RemoteAssistance\.QuickAssist\\/ nocase ascii wide
                        $string11_QuickAssist_greyware_tool_keyword = /\\microsoft\.remoteassistance\.quickassist\\/ nocase ascii wide
                        $string12_QuickAssist_greyware_tool_keyword = /\\Quick\sAssist\sInstaller\.exe/ nocase ascii wide
                        $string13_QuickAssist_greyware_tool_keyword = /\\QuickAssist\.exe/ nocase ascii wide
                        $string14_QuickAssist_greyware_tool_keyword = /\\QuickAssist\.pdb/ nocase ascii wide
                        $string15_QuickAssist_greyware_tool_keyword = /\\SOFTWARE\\Microsoft\\Tracing\\Quick\sAssist\sInstaller/ nocase ascii wide
                        $string16_QuickAssist_greyware_tool_keyword = /\\WindowsApps\\MicrosoftCorporationII\.QuickAssist_/ nocase ascii wide
                        $string17_QuickAssist_greyware_tool_keyword = /\\WinSxS\\amd64_microsoft\-windows\-quickassist_/ nocase ascii wide
                        $string18_QuickAssist_greyware_tool_keyword = "<Provider Name='Quick Assist'/>" nocase ascii wide
                        $string19_QuickAssist_greyware_tool_keyword = ">Quick Assist Component<" nocase ascii wide
                        $string20_QuickAssist_greyware_tool_keyword = /Assistencia\sRapida\sInstaller\.exe/ nocase ascii wide
                        $string21_QuickAssist_greyware_tool_keyword = /Command\:\sbeginsharing\sResult\:\s\{\\"responsename\\"\:\\"beginsharing\\"/ nocase ascii wide
                        $string22_QuickAssist_greyware_tool_keyword = /contactsupportrelays4\-prod\.eastus\.cloudapp\.azure\.com/ nocase ascii wide
                        $string23_QuickAssist_greyware_tool_keyword = /https\:\/\/rdprelay.{0,1000}\.support\.services\.microsoft\.com/ nocase ascii wide
                        $string24_QuickAssist_greyware_tool_keyword = /https\:\/\/remoteassistance\.support\.services\.microsoft\.com\// nocase ascii wide
                        $string25_QuickAssist_greyware_tool_keyword = /Incoming\scmd\sMessage\:\s\{\\"command\\"\:\\"beginsharing\\"/ nocase ascii wide
                        $string26_QuickAssist_greyware_tool_keyword = /Info\:\s\{\\"command\\"\:\\"forwardtoagent\\"\,\s\\"context\\"\:\{\\"command\\"\:\\"requestresponse\\"\,\\"context\\"\:\{\\"responsename\\"\:\\"beginsharing/ nocase ascii wide
                        $string27_QuickAssist_greyware_tool_keyword = /Info\:\s\{\\"command\\"\:\\"rdp_native_event\\"\,\s\\"context\\"\:\{\s\\"eventname\\"\:\\"rdp_native_relay_connection_succeeded\\"\}\s/ nocase ascii wide
                        $string28_QuickAssist_greyware_tool_keyword = /QuickAssist\.exe\slaunched/ nocase ascii wide
                        $string29_QuickAssist_greyware_tool_keyword = /SOFTWARE\\Microsoft\\QuickAssist/ nocase ascii wide
                        $string30_QuickAssist_greyware_tool_keyword = /Szybka\spomoc\sInstaller\.exe/ nocase ascii wide

    condition:
        any of them
}