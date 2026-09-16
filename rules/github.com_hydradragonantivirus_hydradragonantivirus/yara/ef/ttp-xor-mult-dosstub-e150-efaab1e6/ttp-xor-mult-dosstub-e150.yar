rule TTP_XOR_MULT_DOSStub_e150 {
  strings:
    $key_e150 = { b5 38 [2] c1 20 [2] 86 22 [2] c1 33 [2] 8f 3f [2] 83 35 [2] 94 3e [2] 8f 70 [2] b2 }

  condition:
    any of them
}