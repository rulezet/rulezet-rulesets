rule aachum_REMUS
{
    meta:
        author                      = "Izan Perez Perpen (aachum)"
        description                 = "Detects REMUS infostealer/loader. Covers stage 1 binary and stage 2 memory dump."
        date                        = "2026-03-27"
        sha256_s1                   = "cfcb21d8df942918f7a74b99f2cccf7e54e2a6dd1ea6de60897ff0026a26b5c4"
        sha256_s2                   = "352721b32ec1c8349985ceccfec8d1ca6e3e6cc12f83350c4ae1a75477588bc2"
        reference                   = "https://aachum.github.io/website/remus_analysis"
        tlp                         = "TLP:WHITE"
        yarahub_uuid                = "0c21e528-24d9-4195-8e7b-62cf7c63b58d"
        yarahub_license             = "CC0 1.0"
        yarahub_rule_matching_tlp   = "TLP:WHITE"
        yarahub_rule_sharing_tlp    = "TLP:WHITE"
        yarahub_reference_md5       = "d7ac5af95057311fcc244eb4398406ad"

    strings:
        $b64_alpha = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789#-" ascii
        $remus_log = "# REMUS LOG" ascii
        $rpc = "eth.llamarpc.com" ascii wide

        $access_token = "access_token=" ascii
        $debug_param  = "&debug=" ascii
        $step_param   = "access_token=&step=1" ascii

        $pst = "honey@pot.com.pst" ascii
        $runasinvoker = "__COMPAT_LAYER=RunAsInvoker" ascii

        $ps1  = "powershell -exec bypass -f \\\"" ascii
        $rdll = "rundll32 \\\"" ascii

        $multipart_file = "Content-Disposition: form-data; name=\"file\"; filename=\"" ascii
        $multipart_ct   = "Content-Type: multipart/form-data; boundary=" ascii

        $xor_loop = {
            0F B7 44 ?? ?? 
            66 ?? ?? 
            66 31 ?? ?? 
            FF C? ?? ?? ?? ??
        }

        $dispatch = {
            0F B6 C?
            48 8D ?? ?? ?? ?? ?? ??
            FF 24 C?
        }

        $mt_const = { 65 89 07 6C }

        $hash_winhttpopen = { BA 3E E1 45 0E }
        $hash_winhttpsend = { BA 81 B5 AC 92 }
        $hash_openmutex   = { BA FE 0C A5 23 }

    condition:
        uint16(0) == 0x5A4D
        and uint32(uint32(0x3C)) == 0x00004550
        and (
            ($remus_log and $rpc)
            or ($access_token and $debug_param and $pst)
            or ($step_param and $access_token)
            or ($b64_alpha and $remus_log)
            or ($xor_loop and $dispatch and $mt_const)
            or (
                (2 of ($hash_winhttpopen, $hash_winhttpsend, $hash_openmutex))
                and
                (1 of ($rpc, $access_token, $remus_log))
            )
            or ($ps1 and $rdll and $runasinvoker and $multipart_file and $multipart_ct)
        )
}