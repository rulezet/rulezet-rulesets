rule TTP_XOR_MULT_DOSStub_ff65 {
  strings:
    $key_ff65 = { ab 0d [2] df 15 [2] 98 17 [2] df 06 [2] 91 0a [2] 9d 00 [2] 8a 0b [2] 91 45 [2] ac }

  condition:
    any of them
}