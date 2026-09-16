rule MAL_Linux_IoT_MultiArch_BotnetLoader_Generic
{
    meta:
        author = "Anish Bogati"
        description = "Technique-based detection of IoT/Linux botnet loader shell scripts downloading binaries from numeric IPs, chmodding, and executing multi-architecture payloads"
        date = "2025-12-01"
        yarahub_reference_md5       = "e72fbbe6906052e1d8f3546644602849"
        yarahub_uuid                = "4b0e3b57-6d91-4c3a-8f5d-0d7c6b2ff101"
        yarahub_license             = "CC0 1.0"
        yarahub_rule_matching_tlp   = "TLP:WHITE"
        yarahub_rule_sharing_tlp    = "TLP:WHITE"
        reference                   = "MalwareBazaar sample lilin.sh"
        yarahub_reference_link      = "https://bazaar.abuse.ch/sample/8cc4dbecbbd2d5dcd4722a63b936a694893aefa99db815284117a325d19f2fdc/"
        reference_sha256            = "8cc4dbecbbd2d5dcd4722a63b936a694893aefa99db815284117a325d19f2fdc"


    strings:
                $wget1    = "wget http://" ascii
        $wget2    = "wget -q http://" ascii
        $bb_wget  = "busybox wget" ascii
        $curl1    = "curl -fsS" ascii
        $curl2    = "curl -fsSO http://" ascii

                $re_ip_http = /http:\/\/[0-9]{1,3}(\.[0-9]{1,3}){3}(:[0-9]{1,5})?\/[A-Za-z0-9._\-\/]+/ ascii

                $chmod1  = "chmod 777" ascii
        $chmod2  = "chmod +x" ascii

                        $re_ext_arch = /\.(mips(el)?|arm(v[4567]l|5|6|7)?|x86(_64)?|m68k|ppc|sparc|spc|sh4|arc700|i[3456]86)\b/ ascii

                        $re_exec_arch = /\.\/[A-Za-z0-9._\-]*(mips(el)?|arm(v[4567]l|5|6|7)?|x86(_64)?|m68k|ppc|sparc|spc|sh4|arc700|i[3456]86)\b/ ascii

    condition:
                filesize < 50KB and
        uint32(0) != 0x7F454C46 and          uint16(0) != 0x4D5A and      
                ( $wget1 or $wget2 or $bb_wget or $curl1 or $curl2 ) and

                #re_ip_http >= 1 and

                ( $chmod1 or $chmod2 ) and

                        ( #re_ext_arch + #re_exec_arch ) >= 2
}