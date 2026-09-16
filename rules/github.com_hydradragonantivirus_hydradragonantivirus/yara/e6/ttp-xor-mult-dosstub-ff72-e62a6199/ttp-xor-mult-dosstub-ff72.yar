rule TTP_XOR_MULT_DOSStub_ff72 {
  strings:
    $key_ff72 = { ab 1a [2] df 02 [2] 98 00 [2] df 11 [2] 91 1d [2] 9d 17 [2] 8a 1c [2] 91 52 [2] ac }

  condition:
    any of them
}