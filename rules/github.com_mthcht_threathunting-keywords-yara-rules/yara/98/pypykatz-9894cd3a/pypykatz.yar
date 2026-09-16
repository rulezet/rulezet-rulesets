rule pypykatz
{
    meta:
        description = "Detection patterns for the tool 'pypykatz' taken from the ThreatHunting-Keywords github project"
        author = "@mthcht"
        reference = "https://github.com/mthcht/ThreatHunting-Keywords"
        tool = "pypykatz"
        rule_category = "offensive_tool_keyword"

    strings:
                        $string1 = /\sdpapi\sblob\s.{0,100}\.json\s.{0,100}\.dat/ nocase ascii wide
                        $string2 = /\sdpapi\scredential\s.{0,100}\.json\scred/ nocase ascii wide
                        $string3 = " dpapi masterkey /root/" nocase ascii wide
                        $string4 = /\sdpapi\sminidump\s.{0,100}\.dmp/ nocase ascii wide
                        $string5 = /\sdpapi\sprekey\snt\s.{0,100}S\-1\-5\-21/ nocase ascii wide
                        $string6 = " dpapi prekey password " nocase ascii wide
                        $string7 = /\sdpapi\sprekey\sregistry\s.{0,100}\.reg/ nocase ascii wide
                        $string8 = /\sdpapi\ssecurestring\s.{0,100}\.dat/ nocase ascii wide
                        $string9 = " kerberos asreproast " nocase ascii wide
                        $string10 = /\skerberos\sbrute\s.{0,100}\s\-d\s/ nocase ascii wide
                        $string11 = /\skerberos\sbrute\s.{0,100}\.txt/ nocase ascii wide
                        $string12 = /\skerberos\sccache\sdel\s.{0,100}\.ccache/ nocase ascii wide
                        $string13 = " kerberos ccache exportkirbi " nocase ascii wide
                        $string14 = /\skerberos\sccache\slist\s.{0,100}\.ccache/ nocase ascii wide
                        $string15 = " kerberos ccache loadkirbi " nocase ascii wide
                        $string16 = " kerberos ccache roast " nocase ascii wide
                        $string17 = /\skerberos\skeytab\s.{0,100}\.keytab/ nocase ascii wide
                        $string18 = " kerberos kirbi parse " nocase ascii wide
                        $string19 = " kerberos spnroast " nocase ascii wide
                        $string20 = /\slive\sdpapi\sblobfile\s.{0,100}\.blob/ nocase ascii wide
                        $string21 = " live dpapi cred " nocase ascii wide
                        $string22 = " live dpapi keys -o " nocase ascii wide
                        $string23 = " live dpapi securestring " nocase ascii wide
                        $string24 = " live dpapi vcred " nocase ascii wide
                        $string25 = " live dpapi vpol " nocase ascii wide
                        $string26 = " live dpapi wifi" nocase ascii wide
                        $string27 = " live kerberos apreq " nocase ascii wide
                        $string28 = " live kerberos dump" nocase ascii wide
                        $string29 = " live kerberos purge" nocase ascii wide
                        $string30 = " live kerberos roast" nocase ascii wide
                        $string31 = " live kerberos sessions" nocase ascii wide
                        $string32 = " live kerberos tgt" nocase ascii wide
                        $string33 = " live kerberos triage" nocase ascii wide
                        $string34 = " live lsa -o " nocase ascii wide
                        $string35 = " live lsa -o " nocase ascii wide
                        $string36 = " live process create -c regedit" nocase ascii wide
                        $string37 = " live smb client " nocase ascii wide
                        $string38 = " live smb dcsync " nocase ascii wide
                        $string39 = " live smb lsassdump " nocase ascii wide
                        $string40 = " live smb regdump " nocase ascii wide
                        $string41 = " live smb secretsdump " nocase ascii wide
                        $string42 = " live smbapi localgroup enum -t" nocase ascii wide
                        $string43 = " live smbapi session enum " nocase ascii wide
                        $string44 = " live smbapi share enum" nocase ascii wide
                        $string45 = " live users whoami" nocase ascii wide
                        $string46 = /\slsa\sminidump\s.{0,100}\s\-o\s/ nocase ascii wide
                        $string47 = /\slsa\sminidump\s.{0,100}\.dmp/ nocase ascii wide
                        $string48 = " lsa minidump /" nocase ascii wide
                        $string49 = /\ssmb\sclient\s.{0,100}\sshares\s.{0,100}use\sc\$/ nocase ascii wide
                        $string50 = /\ssmb\sshareenum\s.{0,100}smb2\+ntlm\-password/ nocase ascii wide
                        $string51 = /\.py\s\srekall\s.{0,100}\.dmp.{0,100}\s\-t\s0/ nocase ascii wide
                        $string52 = /\/kerberosticket\.py/ nocase ascii wide
                        $string53 = /\/lsass\.DMP/ nocase ascii wide
                        $string54 = "/pypykatz" nocase ascii wide
                        $string55 = /\/ssp\/decryptor\.py/ nocase ascii wide
                        $string56 = /\\\\c\$\\Windows\\Temp\\.{0,100}\.dmp/ nocase ascii wide
                        $string57 = /\\lsass\.DMP/ nocase ascii wide
                        $string58 = /\\x44\\x8b\\x01\\x44\\x39\\x42/ nocase ascii wide
                        $string59 = /\\x83\\x64\\x24\\x30\\x00\\x48\\x8d\\x45\\xe0\\x44\\x8b\\x4d\\xd8\\x48\\x8d\\x15/ nocase ascii wide
                        $string60 = /\\x8b\\x31\\x39\\x72\\x10\\x75/ nocase ascii wide
                        $string61 = /_dcsync\.txt/ nocase ascii wide
                        $string62 = /_lsass\.txt/ nocase ascii wide
                        $string63 = /_lsassdecrypt\.py/ nocase ascii wide
                        $string64 = /apypykatz\.py/ nocase ascii wide
                        $string65 = /asreproast_.{0,100}\.txt/ nocase ascii wide
                        $string66 = /dcsync\.py/ nocase ascii wide
                        $string67 = /dpapi\/decryptor\.py/ nocase ascii wide
                        $string68 = "get_masterkeys_from_lsass" nocase ascii wide
                        $string69 = /gppassword\.py/ nocase ascii wide
                        $string70 = "import apypykatz" nocase ascii wide
                        $string71 = "import pypykatz" nocase ascii wide
                        $string72 = /info\@skelsecprojects\.com/ nocase ascii wide
                        $string73 = "install pypykatz" nocase ascii wide
                        $string74 = "KatzSystemArchitecture" nocase ascii wide
                        $string75 = /kerberos\/decryptor\.py/ nocase ascii wide
                        $string76 = "KIWI_CLOUDAP_LOGON_LIST_ENTRY_21H2" nocase ascii wide
                        $string77 = /lsa_decryptor\.py/ nocase ascii wide
                        $string78 = /lsa_decryptor_nt.{0,100}\.py/ nocase ascii wide
                        $string79 = "LSASecretDefaultPassword" nocase ascii wide
                        $string80 = /minidump.{0,100}minikerberos/ nocase ascii wide
                        $string81 = "pypykatz " nocase ascii wide
                        $string82 = /pypykatz\.commons/ nocase ascii wide
                        $string83 = /pypykatz\.dpapi/ nocase ascii wide
                        $string84 = /pypykatz\.exe/ nocase ascii wide
                        $string85 = /pypykatz\.git/ nocase ascii wide
                        $string86 = /pypykatz\.kerberos/ nocase ascii wide
                        $string87 = /pypykatz\.lsadecryptor/ nocase ascii wide
                        $string88 = /pypykatz\.py/ nocase ascii wide
                        $string89 = /pypykatz\.registry/ nocase ascii wide
                        $string90 = /pypykatz_rekall\.py/ nocase ascii wide
                        $string91 = /pypykatz\-master\.zip/ nocase ascii wide
                        $string92 = /rekallreader\.py/ nocase ascii wide
                        $string93 = /shareenum\.py/ nocase ascii wide
                        $string94 = /spnroast_.{0,100}\.txt/ nocase ascii wide
                        $string95 = /tasklist\s\/fi\s.{0,100}Imagename\seq\slsass\.exe/ nocase ascii wide
                        $string96 = /tspkg\/decryptor\.py/ nocase ascii wide
                        $string97 = /wdigest\/decryptor\.py/ nocase ascii wide
        $metadata_regex_import = /\bimport\s+[a-zA-Z0-9_.]+\b/ nocase
        $metadata_regex_function = /function\s+[a-zA-Z_][a-zA-Z0-9_]*\(/ nocase ascii
        $metadata_regex_php = /<\?php/ nocase ascii
        $metadata_regex_createobject = /(CreateObject|WScript\.)/ nocase ascii
        $metadata_regex_script = /<script\b/ nocase ascii
        $metadata_regex_javascript = /(let\s|const\s|function\s|document\.|console\.)/ nocase ascii
        $metadata_regex_powershell = /(Write-Host|Get-[a-zA-Z]+|Invoke-|param\(|\.SYNOPSIS)/ nocase ascii
        $metadata_regex_batch = /@(echo\s|call\s|set\s|goto\s|if\s|for\s|rem\s)/ nocase ascii
        $metadata_regex_shebang = /^#!\// nocase ascii

    condition:
        ((filesize < 20MB and (
            uint16(0) == 0x5a4d or             uint16(0) == 0x457f or             uint32be(0) == 0x7f454c46 or uint16(0) == 0xfeca or uint16(0) == 0xfacf or uint32(0) == 0xbebafeca or             uint32(0) == 0x504B0304 or             uint32(0) == 0xCAFEBABE or             uint32(0) == 0x4D534346 or             uint32(0) == 0xD0CF11E0 or             uint16(0) == 0x2321 or             uint16(0) == 0x3c3f         )) and 2 of ($string*)) or
        (filesize < 2MB and
        (
            2 of ($string*) and
            for any of ($metadata_regex_*) : ( @ <= 20000 )
        ))
}