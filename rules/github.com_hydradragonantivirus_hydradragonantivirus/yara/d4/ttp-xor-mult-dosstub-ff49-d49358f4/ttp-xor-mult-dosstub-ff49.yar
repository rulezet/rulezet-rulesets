rule TTP_XOR_MULT_DOSStub_ff49 {
  strings:
    $key_ff49 = { ab 21 [2] df 39 [2] 98 3b [2] df 2a [2] 91 26 [2] 9d 2c [2] 8a 27 [2] 91 69 [2] ac }

  condition:
    any of them
}