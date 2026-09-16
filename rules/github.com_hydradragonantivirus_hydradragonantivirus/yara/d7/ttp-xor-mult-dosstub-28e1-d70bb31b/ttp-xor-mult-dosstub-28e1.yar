rule TTP_XOR_MULT_DOSStub_28e1 {
  strings:
    $key_28e1 = { 7c 89 [2] 08 91 [2] 4f 93 [2] 08 82 [2] 46 8e [2] 4a 84 [2] 5d 8f [2] 46 c1 [2] 7b }

  condition:
    any of them
}