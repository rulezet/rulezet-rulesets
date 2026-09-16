rule TTP_XOR_MULT_DOSStub_ffc7 {
  strings:
    $key_ffc7 = { ab af [2] df b7 [2] 98 b5 [2] df a4 [2] 91 a8 [2] 9d a2 [2] 8a a9 [2] 91 e7 [2] ac }

  condition:
    any of them
}