rule TTP_XOR_MULT_DOSStub_ff74 {
  strings:
    $key_ff74 = { ab 1c [2] df 04 [2] 98 06 [2] df 17 [2] 91 1b [2] 9d 11 [2] 8a 1a [2] 91 54 [2] ac }

  condition:
    any of them
}