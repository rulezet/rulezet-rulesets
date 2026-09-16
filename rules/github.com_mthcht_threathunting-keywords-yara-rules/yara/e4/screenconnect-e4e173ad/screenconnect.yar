rule ScreenConnect
{
    meta:
        description = "Detection patterns for the tool 'ScreenConnect' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "ScreenConnect"
        rule_category = "greyware_tool_keyword"

    strings:
                        $string1 = /\:8040\/SetupWizard\.aspx/ nocase ascii wide
                        $string2 = /\\CurrentControlSet\\Control\\SafeBoot\\Network\\ScreenConnect\sClient\s\(/ nocase ascii wide
                        $string3 = /\\CurrentControlSet\\Services\\ScreenConnect\s/ nocase ascii wide
                        $string4 = /\\Documents\\ConnectWiseControl\\Files/ nocase ascii wide
                        $string5 = /\\InventoryApplicationFile\\screenconnect\.cl/ nocase ascii wide
                        $string6 = /\\InventoryApplicationFile\\screenconnect\.wi/ nocase ascii wide
                        $string7 = /\\ScreenConnect\sClient\s\(/ nocase ascii wide
                        $string8 = /\\ScreenConnect\.Client\.exe/ nocase ascii wide
                        $string9 = /\\ScreenConnect\.ClientService\.exe/ nocase ascii wide
                        $string10 = /\\ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
                        $string11 = /\\ScreenConnect\.Core\.dll/ nocase ascii wide
                        $string12 = /\\ScreenConnect\.InstallerActions\.dll/ nocase ascii wide
                        $string13 = /\\ScreenConnect\.Windows\.dll/ nocase ascii wide
                        $string14 = /\\ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
                        $string15 = /\\ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
                        $string16 = /\\ScreenConnect\\Bin\\/ nocase ascii wide
                        $string17 = /\\TEMP\\ScreenConnect\\.{0,1000}\.ps1/ nocase ascii wide
                        $string18 = /\\Temp\\ScreenConnect\\.{0,1000}\\setup\.msi/ nocase ascii wide
                        $string19 = /\\Windows\\Temp\\ScreenConnect\\.{0,1000}\.cmd/ nocase ascii wide
                        $string20 = /\\Windows\\Temp\\ScreenConnect\\.{0,1000}\.ps1/ nocase ascii wide
                        $string21 = "<Data>ScreenConnect Software</Data>" nocase ascii wide
                        $string22 = "<Provider Name='ScreenConnect Security Manager'/>" nocase ascii wide
                        $string23 = "<Provider Name='ScreenConnect Web Server'/>" nocase ascii wide
                        $string24 = /cmd\.exe.{0,1000}\\TEMP\\ScreenConnect\\.{0,1000}\.cmd/ nocase ascii wide
                        $string25 = /https\:\/\/.{0,1000}\.screenconnect\.com\/Bin\/.{0,1000}\.exe/ nocase ascii wide
                        $string26 = /https\:\/\/.{0,1000}\.screenconnect\.com\/Host/ nocase ascii wide
                        $string27 = /https\:\/\/cloud\.screenconnect\.com\/\#\/trialtoinstance\?cookieValue\=/ nocase ascii wide
                        $string28 = /Program\sFiles\s\(x86\)\\ScreenConnect\sClient/ nocase ascii wide
                        $string29 = /\-relay\.screenconnect\.com/ nocase ascii wide
                        $string30 = "ScreenConnect Software" nocase ascii wide
                        $string31 = /ScreenConnect\.Client\.dll/ nocase ascii wide
                        $string32 = /ScreenConnect\.Client\.exe\.jar/ nocase ascii wide
                        $string33 = /ScreenConnect\.ClientService\.dll/ nocase ascii wide
                        $string34 = /ScreenConnect\.ClientService\.exe/ nocase ascii wide
                        $string35 = /ScreenConnect\.ClientSetup\.exe/ nocase ascii wide
                        $string36 = /SCREENCONNECT\.CLIENTSETUP\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string37 = /ScreenConnect\.ClientUninstall\.vbs/ nocase ascii wide
                        $string38 = /ScreenConnect\.Core\.pdb/ nocase ascii wide
                        $string39 = /ScreenConnect\.Server\.dll/ nocase ascii wide
                        $string40 = /ScreenConnect\.Service\.exe/ nocase ascii wide
                        $string41 = /SCREENCONNECT\.SERVICE\.EXE\-.{0,1000}\.pf/ nocase ascii wide
                        $string42 = /ScreenConnect\.WindowsBackstageShell\.exe/ nocase ascii wide
                        $string43 = /SCREENCONNECT\.WINDOWSCLIENT\..{0,1000}\.pf/ nocase ascii wide
                        $string44 = /ScreenConnect\.WindowsClient\.exe/ nocase ascii wide
                        $string45 = /ScreenConnect\.WindowsInstaller\.dll/ nocase ascii wide
                        $string46 = /ScreenConnect_.{0,1000}_Release\.msi/ nocase ascii wide
                        $string47 = /ScreenConnect_.{0,1000}_Release\.tar\.gz/ nocase ascii wide
                        $string48 = /ScreenConnect_.{0,1000}_Release\.zip/ nocase ascii wide
                        $string49 = /ScreenConnectClientNetworkDeployer\.exe/ nocase ascii wide
                        $string50 = /server.{0,1000}\-relay\.screenconnect\.com/ nocase ascii wide
                        $string51 = /\-web\.screenconnect\.com/ nocase ascii wide

    condition:
        any of them
}