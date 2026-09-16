rule SecuriteInfo_Qakbot_1 {
  meta:
    author = "Arnaud Jacques / SecuriteInfo.com"

  strings:
    $a1 = "Function(\"url\", body.replace(/5&/g, \"\"));"

  condition:
    $a1
}