rule PEiD_00393_Com4mail_v1_0_ {
  meta:
    description = "[Com4mail v1.0]"
    ep_only     = "true"

  strings:
    $a = "BEGIN===tfud#of_Com4Mail_file#\r\n"

  condition:
    $a
}