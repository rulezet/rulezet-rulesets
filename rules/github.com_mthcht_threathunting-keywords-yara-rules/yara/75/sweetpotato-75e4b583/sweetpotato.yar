rule SweetPotato
{
    meta:
        description = "Detection patterns for the tool 'SweetPotato' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "SweetPotato"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = " --exploit=DCOM" nocase ascii wide
                        $string2 = " --exploit=DCOM" nocase ascii wide
                        $string3 = " --exploit=EfsRpc" nocase ascii wide
                        $string4 = " --exploit=PrintSpoofer" nocase ascii wide
                        $string5 = " --exploit=WinRM" nocase ascii wide
                        $string6 = /\sSweetpotato\.exe/ nocase ascii wide
                        $string7 = /\/Sweetpotato\.exe/ nocase ascii wide
                        $string8 = /\/SweetPotato\.git/ nocase ascii wide
                        $string9 = /\/SweetPotato\-master\.zip/ nocase ascii wide
                        $string10 = /\[\+\]\sAttempting\sDCOM\sNTLM\srelaying\swith\sCLSID/ nocase ascii wide
                        $string11 = /\[\+\]\sAttempting\sNP\simpersonation\susing\smethod\sEfsRpc\sto\slaunch\s/ nocase ascii wide
                        $string12 = /\[\+\]\sAttempting\sNP\simpersonation\susing\smethod\sPrintSpoofer\sto\slaunch\s/ nocase ascii wide
                        $string13 = /\[\+\]\sServer\sconnected\sto\sour\sevil\sRPC\spipe/ nocase ascii wide
                        $string14 = /\[\+\]\sTriggering\sname\spipe\saccess\son\sevil\sPIPE\s/ nocase ascii wide
                        $string15 = /\\Sweetpotato\.exe/ nocase ascii wide
                        $string16 = /\\SweetPotato\\Program\.cs/ nocase ascii wide
                        $string17 = /\\SweetPotato\-master\.zip/ nocase ascii wide
                        $string18 = "1BF9C10F-6F89-4520-9D2E-AAF17D17BA5E" nocase ascii wide
                        $string19 = "8f2a1d66e0a532a030da8e0e646f866ea91ee987ffb33b36d95f64a0538a3e20" nocase ascii wide
                        $string20 = "CCob/SweetPotato" nocase ascii wide
                        $string21 = /PotatoAPI\.Mode\.DCOMRemote/ nocase ascii wide
                        $string22 = "Remote Potato by @decoder_it and @splinter_code" nocase ascii wide
                        $string23 = "SweetPotato by @_EthicalChaos_" nocase ascii wide
                        $string24 = "Weaponized JuciyPotato by @decoder_it and @Guitro along with BITS WinRM discovery" nocase ascii wide

    condition:
        any of them
}