rule TTP_XOR_MULT_DOSStub_54ea {
  strings:
    $key_54ea = { 00 82 [2] 74 9a [2] 33 98 [2] 74 89 [2] 3a 85 [2] 36 8f [2] 21 84 [2] 3a ca [2] 07 }

  condition:
    any of them
}