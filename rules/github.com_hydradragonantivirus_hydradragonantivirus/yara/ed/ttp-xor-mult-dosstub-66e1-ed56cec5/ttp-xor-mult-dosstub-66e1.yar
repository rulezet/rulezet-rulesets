rule TTP_XOR_MULT_DOSStub_66e1 {
  strings:
    $key_66e1 = { 32 89 [2] 46 91 [2] 01 93 [2] 46 82 [2] 08 8e [2] 04 84 [2] 13 8f [2] 08 c1 [2] 35 }

  condition:
    any of them
}