rule QuickAssist
{
    meta:
        description = "Detection patterns for the tool 'QuickAssist' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "QuickAssist"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\s\-\-webview\-exe\-name\=QuickAssist\.exe/ nocase ascii wide
                        $string2 = /\/Assistance\srapide\sInstaller\.exe/ nocase ascii wide
                        $string3 = /\/Assistenza\srapida\sInstaller\.exe/ nocase ascii wide
                        $string4 = /\/Quick\sAssist\sInstaller\.exe/ nocase ascii wide
                        $string5 = /\/Quick\%20Assist\%20Installer\.exe/ nocase ascii wide
                        $string6 = /\\AppData\\Local\\Temp\\RemoteHelp\\EBWebView/ nocase ascii wide
                        $string7 = /\\Assistance\srapide\sInstaller\.exe/ nocase ascii wide
                        $string8 = /\\Assistenza\srapida\sInstaller\.exe/ nocase ascii wide
                        $string9 = /\\CurrentControlSet\\Services\\bam\\State\\UserSettings\\.{0,1000}\\MicrosoftCorporationII\.QuickAssist_/ nocase ascii wide
                        $string10 = /\\Microsoft\.RemoteAssistance\.QuickAssist\\/ nocase ascii wide
                        $string11 = /\\microsoft\.remoteassistance\.quickassist\\/ nocase ascii wide
                        $string12 = /\\Quick\sAssist\sInstaller\.exe/ nocase ascii wide
                        $string13 = /\\QuickAssist\.exe/ nocase ascii wide
                        $string14 = /\\QuickAssist\.pdb/ nocase ascii wide
                        $string15 = /\\SOFTWARE\\Microsoft\\Tracing\\Quick\sAssist\sInstaller/ nocase ascii wide
                        $string16 = /\\WindowsApps\\MicrosoftCorporationII\.QuickAssist_/ nocase ascii wide
                        $string17 = /\\WinSxS\\amd64_microsoft\-windows\-quickassist_/ nocase ascii wide
                        $string18 = "<Provider Name='Quick Assist'/>" nocase ascii wide
                        $string19 = ">Quick Assist Component<" nocase ascii wide
                        $string20 = /Assistencia\sRapida\sInstaller\.exe/ nocase ascii wide
                        $string21 = /Command\:\sbeginsharing\sResult\:\s\{\\"responsename\\"\:\\"beginsharing\\"/ nocase ascii wide
                        $string22 = /contactsupportrelays4\-prod\.eastus\.cloudapp\.azure\.com/ nocase ascii wide
                        $string23 = /https\:\/\/rdprelay.{0,1000}\.support\.services\.microsoft\.com/ nocase ascii wide
                        $string24 = /https\:\/\/remoteassistance\.support\.services\.microsoft\.com\// nocase ascii wide
                        $string25 = /Incoming\scmd\sMessage\:\s\{\\"command\\"\:\\"beginsharing\\"/ nocase ascii wide
                        $string26 = /Info\:\s\{\\"command\\"\:\\"forwardtoagent\\"\,\s\\"context\\"\:\{\\"command\\"\:\\"requestresponse\\"\,\\"context\\"\:\{\\"responsename\\"\:\\"beginsharing/ nocase ascii wide
                        $string27 = /Info\:\s\{\\"command\\"\:\\"rdp_native_event\\"\,\s\\"context\\"\:\{\s\\"eventname\\"\:\\"rdp_native_relay_connection_succeeded\\"\}\s/ nocase ascii wide
                        $string28 = /QuickAssist\.exe\slaunched/ nocase ascii wide
                        $string29 = /SOFTWARE\\Microsoft\\QuickAssist/ nocase ascii wide
                        $string30 = /Szybka\spomoc\sInstaller\.exe/ nocase ascii wide

    condition:
        any of them
}