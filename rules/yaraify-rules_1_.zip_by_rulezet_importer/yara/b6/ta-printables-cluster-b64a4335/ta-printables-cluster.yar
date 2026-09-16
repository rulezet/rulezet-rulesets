rule TA_Printables_Cluster
{
    meta:
        id = "TA001"
        version = "1.0"
        date = "2026-05-24"
        modified = "2026-05-24"
        status = "RELEASED"
        sharing = "TLP:CLEAR"
        author = "frexna"
        description = "Detects Python RAT, Pyramid, Fernet, zlib/base64 and pythonmemorymodule artifacts"
        category = "MALWARE"
        malware = "PYTHON_RAT"
        mitre_att = "T1027,T1059,T1105"
        yarahub_uuid = "5a4f4c2e-3a1c-4f21-9c61-7bb5f1d00a11"
        yarahub_license = "CC0 1.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "d41d8cd98f00b204e9800998ecf8427e"

    strings:
        $fernet_1 = "from cryptography.fernet import Fernet" ascii
        $fernet_2 = "Fernet(" ascii
        $pyramid_1 = "from pyramid.config import Configurator" ascii
        $pyramid_2 = "pyramid.response" ascii
        $memory_1 = "pythonmemorymodule" ascii nocase
        $memory_2 = "MemoryModule" ascii
        $enc_1 = "zlib.decompress" ascii
        $enc_2 = "base64.b64decode" ascii
        $enc_3 = "from base64 import b64decode" ascii

    condition:
        filesize < 10MB and
        (
            2 of ($fernet_*) or
            2 of ($pyramid_*) or
            any of ($memory_*) or
            ($enc_1 and 1 of ($enc_*))
        )
}