rule win_x86_x64_Mirai {
    meta:
        author = "NDA0E"
        yarahub_author_twitter = "@NDA0E"
        date = "2025-01-26"
        description = "Detects Mirai"
        yarahub_uuid = "c0257af9-5608-4c28-8a94-4060ddd22602"
        yarahub_license = "CC BY 4.0"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "800dcb9f93715f5ed7189be2e35aebd9"
        malpedia_family = "win.mirai"
        
    strings:
        $c2_send = {
            4? 8b ??                   ?? ?? ?? ??
            ff d?                      4? 8d ??                   ?? ?? ?? ??
            48 89 ??                   ?? ?? ?? ??
            4? 8b ??                   ?? ?? ?? ??
            4? 89 ??                   e8 ?? ??                   ?? ??
        }

        $c2_recv = {
            4? 8b ??                   ?? ?? ?? ??
            ff d?                      89 ?? ??                   ?? ?? ??
            83 b? ??                   ?? ?? ?? ??
            79 ??                      4? 8d ??                   ?? ?? ?? ??
            e8 ?? ??                   ?? ??
            e9 ?? ??                   ?? ??
        }

    condition:
        all of them
}