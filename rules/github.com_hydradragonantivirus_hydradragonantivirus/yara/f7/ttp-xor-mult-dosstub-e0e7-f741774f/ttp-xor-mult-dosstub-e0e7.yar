rule TTP_XOR_MULT_DOSStub_e0e7 {
  strings:
    $key_e0e7 = { b4 8f [2] c0 97 [2] 87 95 [2] c0 84 [2] 8e 88 [2] 82 82 [2] 95 89 [2] 8e c7 [2] b3 }

  condition:
    any of them
}