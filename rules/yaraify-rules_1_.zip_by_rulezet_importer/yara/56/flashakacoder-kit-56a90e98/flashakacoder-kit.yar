rule flashakacoder_kit
{
    meta:
        yarahub_uuid = "24b498ea-b6b3-4794-9e87-6e784803137f"
        yarahub_license = "CC0 1.0"
        yarahub_author_twitter = "@Lenny_3BO"
        yarahub_rule_matching_tlp = "TLP:WHITE"
        yarahub_rule_sharing_tlp = "TLP:WHITE"
        yarahub_reference_md5 = "6d36b6c335935a07afd917574c27f29e"
        author      = "Lenny-3BO"
        description = "FLASHAKACODER PHP banking kit -- operator tag + admin chain + Telegram exfil + HTML form-action"
        family      = "phishkit.flashakacoder"
        version     = "2.1"
        date        = "2026-05-01"
        reference   = "hunts/flashakacoder-tarrarat-cluster"

    strings:
                $php_open       = "<?php"

                $op_tag         = "FLASHAKACODER" ascii nocase

                $nav_log        = "admin/log.php" ascii
        $nav_log2       = "admin/log2.php" ascii
        $nav_exp        = "admin/exp.php" ascii
        $nav_views      = "admin/views.php" ascii
        $nav_spin       = "admin/spin.php" ascii

                $form_act_log   = "action=\"admin/log.php\"" ascii nocase
        $form_act_log2  = "action=\"admin/log2.php\"" ascii nocase
        $form_act_exp   = "action=\"admin/exp.php\"" ascii nocase
        $form_act_views = "action=\"admin/views.php\"" ascii nocase
        $form_act_spin  = "action=\"admin/spin.php\"" ascii nocase

                $tg_api         = "api.telegram" ascii nocase
        $tg_send        = "sendMessage" ascii
        $tg_chat        = "chat_id" ascii nocase

    condition:
                uint16(0) != 0x5A4D and
        filesize < 2MB and
        (
                        $op_tag
            or
                        ($php_open and 2 of ($nav_log, $nav_log2, $nav_exp, $nav_views, $nav_spin))
            or
                        ($php_open and all of ($tg_api, $tg_send, $tg_chat))
            or
                        (1 of ($form_act_log, $form_act_log2, $form_act_exp, $form_act_views, $form_act_spin))
        )
}