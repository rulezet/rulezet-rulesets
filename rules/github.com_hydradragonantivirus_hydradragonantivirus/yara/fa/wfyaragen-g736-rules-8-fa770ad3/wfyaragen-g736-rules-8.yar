rule WFYARAGEN_G736_rules_8 {
  meta:
    description = "Matches backdoor found in infections - assert-eval"

  strings:
    $re = /if\s*\(\s*\w{1,255}\s*\(\$_(REQUEST|GET|POST|COOKIE)\s*\[\s*'\w{1,255}'\s*\]\s*\)\s*\)\s*\w{1,255}\s*\(\s*stripslashes\s*\(\s*\$_(REQUEST|GET|POST|COOKIE)\s*\[\s*'bot'\s*\]\s*\)\s*\)\s*;/

  condition:
    $re
}