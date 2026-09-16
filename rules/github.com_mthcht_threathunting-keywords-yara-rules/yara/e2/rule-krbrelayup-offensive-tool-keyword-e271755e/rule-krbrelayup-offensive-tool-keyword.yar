rule rule_KrbRelayUp_offensive_tool_keyword
{
    meta:
        description = "Detection patterns for the tool 'KrbRelayUp' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "KrbRelayUp"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1_KrbRelayUp_offensive_tool_keyword = " = \"KRBRELAYUP\"" nocase ascii wide
                        $string2_KrbRelayUp_offensive_tool_keyword = " --ForceShadowCred" nocase ascii wide
                        $string3_KrbRelayUp_offensive_tool_keyword = /\sMakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
                        $string4_KrbRelayUp_offensive_tool_keyword = /\sPowermad\.ps1/ nocase ascii wide
                        $string5_KrbRelayUp_offensive_tool_keyword = /\sspawn\s\-m\sadcs\s\-d\s.{0,1000}\s\-dc\s/ nocase ascii wide
                        $string6_KrbRelayUp_offensive_tool_keyword = " spawn -m shadowcred -d " nocase ascii wide
                        $string7_KrbRelayUp_offensive_tool_keyword = /\.exe\srelay\s\-Domain\s.{0,1000}\s\-CreateNewComputerAccount\s/ nocase ascii wide
                        $string8_KrbRelayUp_offensive_tool_keyword = /\.exe\sspawn\s\-m\srbcd\s\-d\s/ nocase ascii wide
                        $string9_KrbRelayUp_offensive_tool_keyword = /\.exe\sspawn\s\-m\sshadowcred\s\-d\s/ nocase ascii wide
                        $string10_KrbRelayUp_offensive_tool_keyword = /\/KrbRelayUp\.exe/ nocase ascii wide
                        $string11_KrbRelayUp_offensive_tool_keyword = /\/KrbRelayUp\.git/ nocase ascii wide
                        $string12_KrbRelayUp_offensive_tool_keyword = /\/MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
                        $string13_KrbRelayUp_offensive_tool_keyword = /\/Powermad\.ps1/ nocase ascii wide
                        $string14_KrbRelayUp_offensive_tool_keyword = /\[\-\]\sFailed\sto\sdecrypt\sTGT\susing\ssupplied\spassword\/hash\.\sIf\sthis\sTGT\swas\srequested\swith\sno\spreauth\sthen\sthe\spassword\ssupplied\smay\sbe\sincorrect\sor\sthe\sdata\swas\sencrypted\swith\sa\sdifferent\stype\sof\sencryption\sthan\sexpected/ nocase ascii wide
                        $string15_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sBuilding\sS4U2proxy\srequest\sfor\sservice\:\s/ nocase ascii wide
                        $string16_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sBuilding\sS4U2self\s/ nocase ascii wide
                        $string17_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sGetting\scredentials\susing\sU2U/ nocase ascii wide
                        $string18_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sGot\sKrb\sAuth\sfrom\sNT\/System\.\sRelaying\sto\sADCS\snow/ nocase ascii wide
                        $string19_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sGot\sKrb\sAuth\sfrom\sNT\/System\.\sRelaying\sto\sADCS\snow/ nocase ascii wide
                        $string20_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sGot\sKrb\sAuth\sfrom\sNT\/SYSTEM\.\sRelying\sto\sLDAP\snow/ nocase ascii wide
                        $string21_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sGot\sKrb\sAuth\sfrom\sNT\/SYSTEM\.\sRelying\sto\sLDAP\snow/ nocase ascii wide
                        $string22_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sImpersonating\suser\s.{0,1000}\sto\starget\sSPN\s/ nocase ascii wide
                        $string23_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sRun\sthe\sspawn\smethod\sfor\sSYSTEM\sshell\:/ nocase ascii wide
                        $string24_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sS4U2proxy\ssuccess\!/ nocase ascii wide
                        $string25_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sS4U2self\ssuccess\!/ nocase ascii wide
                        $string26_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sSending\sS4U2proxy\srequest\sto\sdomain\scontroller\s/ nocase ascii wide
                        $string27_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sSending\sS4U2proxy\srequest\svia\sKDC\sproxy\:\s/ nocase ascii wide
                        $string28_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sSending\sS4U2proxy\srequest\svia\sKDC\sproxy\:/ nocase ascii wide
                        $string29_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sSending\sS4U2self\srequest\sto\s/ nocase ascii wide
                        $string30_KrbRelayUp_offensive_tool_keyword = /\[\+\]\sSending\sS4U2self\srequest\svia\sKDC\sproxy\:/ nocase ascii wide
                        $string31_KrbRelayUp_offensive_tool_keyword = /\\KrbRelayUp\.exe/ nocase ascii wide
                        $string32_KrbRelayUp_offensive_tool_keyword = /\\KrbRelayUp\.lib/ nocase ascii wide
                        $string33_KrbRelayUp_offensive_tool_keyword = /\\KrbSCM\.cs/ nocase ascii wide
                        $string34_KrbRelayUp_offensive_tool_keyword = /\\MakeMeEnterpriseAdmin\.ps1/ nocase ascii wide
                        $string35_KrbRelayUp_offensive_tool_keyword = /\\Powermad\.ps1/ nocase ascii wide
                        $string36_KrbRelayUp_offensive_tool_keyword = /\\Relay\\Attacks\\ShadowCred\.cs/ nocase ascii wide
                        $string37_KrbRelayUp_offensive_tool_keyword = "3aa113440e9f684df0d0f889c69ae914a40b07c10a340d1fad4f8365286fe19d" nocase ascii wide
                        $string38_KrbRelayUp_offensive_tool_keyword = "Dec0ne/KrbRelayUp" nocase ascii wide
                        $string39_KrbRelayUp_offensive_tool_keyword = "ED83E265-D48E-4B0D-8C22-D9D0A67C78F2" nocase ascii wide
                        $string40_KrbRelayUp_offensive_tool_keyword = "KRB_CRED kirbi " nocase ascii wide
                        $string41_KrbRelayUp_offensive_tool_keyword = /KRB_CRED\(kirbiBytes\)/ nocase ascii wide
                        $string42_KrbRelayUp_offensive_tool_keyword = "KrbRelayUp - Relaying you to SYSTEM" nocase ascii wide
                        $string43_KrbRelayUp_offensive_tool_keyword = /KrbRelayUp\.csproj/ nocase ascii wide
                        $string44_KrbRelayUp_offensive_tool_keyword = /KrbRelayUp\.exe\s/ nocase ascii wide
                        $string45_KrbRelayUp_offensive_tool_keyword = /KrbRelayUp\.exe/ nocase ascii wide
                        $string46_KrbRelayUp_offensive_tool_keyword = /KrbRelayUp\/1\.0/ nocase ascii wide
                        $string47_KrbRelayUp_offensive_tool_keyword = "KRBSCM: Will use the currently loaded Kerberos Service Ticket to create a new service running as SYSTEM" nocase ascii wide
                        $string48_KrbRelayUp_offensive_tool_keyword = "namespace KrbRelayUp" nocase ascii wide
                        $string49_KrbRelayUp_offensive_tool_keyword = /Perform\sfull\sattack\schain\.\sOptions\sare\sidentical\sto\sRELAY\.\sTool\smust\sbe\son\sdisk/ nocase ascii wide
                        $string50_KrbRelayUp_offensive_tool_keyword = /serviceName\s\=\s.{0,1000}\\"KrbSCM\\"/ nocase ascii wide
                        $string51_KrbRelayUp_offensive_tool_keyword = "ServiceName'>KrbSCM" nocase ascii wide
                        $string52_KrbRelayUp_offensive_tool_keyword = /using\sKrbRelayUp\./ nocase ascii wide

    condition:
        any of them
}