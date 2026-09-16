rule CecBot_Attack_ELF
{
    meta:
        author = "Nokia Deepfield ERT"
        description = "CecBot DDoS botnet - libattack.so JNI attack engine"
        date = "2026-03-26"
        family = "CecBot"
        hash = "b3c1d5fc273d19556b09f935b9b09b782b113b98a8a010ebcbb5de5bfce77e67"
        yarahub_uuid = "d7e4a192-5c83-4f6b-b0d9-3e8f2c17a4b6"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "e750c27b9a4fcaa6a048d86c4d011c92"

    strings:
                $jni_init = "Java_com_google_android_update_AttackEngine_nativeInit"
        $jni_start = "Java_com_google_android_update_AttackEngine_nativeStartAttack"
        $jni_kill = "Java_com_google_android_update_AttackEngine_nativeKillAll"
        $jni_count = "Java_com_google_android_update_AttackEngine_nativeGetRunningCount"

                        $tls_ssl = "/system/lib/libssl.so" ascii
        $tls_crypto = "/system/lib/libcrypto.so" ascii

                $h2_alpn = { 02 68 32 08 68 74 74 70 2f 31 2e 31 }  
    condition:
        uint32(0) == 0x464c457f and
        (
                        any of ($jni_*) or

                        ($tls_ssl and $tls_crypto and $h2_alpn)
        )
}