rule TTP_XOR_MULT_DOSStub_ffe6 {
  strings:
    $key_ffe6 = { ab 8e [2] df 96 [2] 98 94 [2] df 85 [2] 91 89 [2] 9d 83 [2] 8a 88 [2] 91 c6 [2] ac }

  condition:
    any of them
}