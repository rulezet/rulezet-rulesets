rule TTP_XOR_MULT_DOSStub_e117 {
  strings:
    $key_e117 = { b5 7f [2] c1 67 [2] 86 65 [2] c1 74 [2] 8f 78 [2] 83 72 [2] 94 79 [2] 8f 37 [2] b2 }

  condition:
    any of them
}