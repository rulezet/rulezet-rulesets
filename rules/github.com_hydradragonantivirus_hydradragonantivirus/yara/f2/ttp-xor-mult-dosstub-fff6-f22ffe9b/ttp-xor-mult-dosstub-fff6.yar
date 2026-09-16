rule TTP_XOR_MULT_DOSStub_fff6 {
  strings:
    $key_fff6 = { ab 9e [2] df 86 [2] 98 84 [2] df 95 [2] 91 99 [2] 9d 93 [2] 8a 98 [2] 91 d6 [2] ac }

  condition:
    any of them
}