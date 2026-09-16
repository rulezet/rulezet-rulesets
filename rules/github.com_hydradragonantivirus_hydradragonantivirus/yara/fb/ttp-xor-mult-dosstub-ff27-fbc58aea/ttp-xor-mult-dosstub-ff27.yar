rule TTP_XOR_MULT_DOSStub_ff27 {
  strings:
    $key_ff27 = { ab 4f [2] df 57 [2] 98 55 [2] df 44 [2] 91 48 [2] 9d 42 [2] 8a 49 [2] 91 07 [2] ac }

  condition:
    any of them
}