rule _20160421_3ed7e80d8a8dc605aec8af75d1697e92_20160421_7693d1d7c6ee_1057 {
  meta:
    description = "datamaliciousorder - from files 20160421_3ed7e80d8a8dc605aec8af75d1697e92.js, 20160421_7693d1d7c6eeb845f7576b1b9b7aa2ed.js, 20160421_fd947780f5e7a6ea8f55848086580d1f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "494dedcd68a9320f24fd348d0c9f4e14578df25190e6c015fd1524dd8cf4af6b"
    hash2       = "d76fd0447debd98d526640646a208112aac644173fb79075f473525f7e06b9e6"
    hash3       = "8ea22d3dcb9e28f5ecdd48dc4433fda0c26e0afa8e6c8fab04343c154b280c57"

  strings:
    $x1  = "Upgrading_WordPress = Choose[\"wpmu_get_blog_allowedthemes\"[\"replace\"](/wpmu_get_blog_allowedthemes/, \"ExpandEnvironmentStri" ascii
    $x2  = "](\"jscripts\"[\"replace\"](/jscripts/, \"%TEMP%/\") + \"single_row_columns\"[\"replace\"](/single_row_columns/, \"5w5xGKQ9WE.ex" ascii
    $s3  = "auto_core_update_email = Choose[\"Checking\"[\"replace\"](/Checking/, \"ExpandEnvironmentStrings\")](\"xml_parser_free\".replace" ascii
    $s4  = "rser_free/, \"%TEMP%/\") + \"Give\"[\"replace\"](/Give/, \"gethchmod.js\"));" fullword ascii
    $s5  = "Choose = wp_get_attachment_image_src[\"itemIndex\"[\"replace\"](/itemIndex/, \"CreateObject\")](\"removal\".replace(/removal/, " ascii
    $s6  = "wp_get_attachment_image_src = this[\"wp_check_post_lock\".replace(/wp_check_post_lock/, \"WScript\")];" fullword ascii
    $s7  = "Choose = wp_get_attachment_image_src[\"itemIndex\"[\"replace\"](/itemIndex/, \"CreateObject\")](\"removal\".replace(/removal/, " ascii
    $s8  = "Upgrading_WordPress = Choose[\"wpmu_get_blog_allowedthemes\"[\"replace\"](/wpmu_get_blog_allowedthemes/, \"ExpandEnvironmentStri" ascii
    $s9  = "must[\"contentinfo\"[\"replace\"](/contentinfo/, \"close\")]();" fullword ascii
    $s10 = "auto_core_update_email = Choose[\"Checking\"[\"replace\"](/Checking/, \"ExpandEnvironmentStrings\")](\"xml_parser_free\".replace" ascii
    $s11 = "must = array_reverse[\"dodelete\".replace(/dodelete/, \"OpenTextFile\")](auto_core_update_email,  + is_rtl, true,  + new_menu_lo" ascii
    $s12 = "must = array_reverse[\"dodelete\".replace(/dodelete/, \"OpenTextFile\")](auto_core_update_email,  + is_rtl, true,  + new_menu_lo" ascii
    $s13 = "must[\"after_plugin_row\".replace(/after_plugin_row/, \"write\")](unescape(\"Armstrong\".replace(/Armstrong/," fullword ascii

  condition:
    (uint16(0) == 0x6176 and (1 of ($x*) and 4 of them)
    ) or (all of them)
}