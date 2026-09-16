rule TTP_XOR_MULT_DOSStub_fff1 {
  strings:
    $key_fff1 = { ab 99 [2] df 81 [2] 98 83 [2] df 92 [2] 91 9e [2] 9d 94 [2] 8a 9f [2] 91 d1 [2] ac }

  condition:
    any of them
}