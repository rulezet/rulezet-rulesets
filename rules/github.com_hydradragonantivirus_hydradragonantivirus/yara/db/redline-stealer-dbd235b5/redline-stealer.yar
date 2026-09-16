rule redline_stealer {
  meta:
    author      = "jeFF0Falltrades"
    hash        = "f64ed3bd7304cdec6e99bb35662aa485e32156c1ca7275fed0c1e67d2f9fc139"
    description = "This rule matches unpacked RedLine Stealer samples and derivatives (as of APR2021)"

  strings:
    $str_0 = "Software\\Valve\\SteamLogin Data" wide ascii
    $str_1 = "name_on_cardencrypted_value" wide ascii
    $str_2 = "card_number_encrypted" wide ascii
    $str_3 = "geoplugin_region!" wide ascii
    $str_4 = "set_GameChatFiles" wide ascii
    $str_5 = "set_ScanDiscord" wide ascii
    $str_6 = "<GameChatFiles>k__BackingField" wide ascii

  condition:
    3 of them
}