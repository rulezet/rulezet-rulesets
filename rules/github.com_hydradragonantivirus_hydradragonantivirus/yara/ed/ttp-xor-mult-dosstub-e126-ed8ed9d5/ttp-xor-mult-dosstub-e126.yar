rule TTP_XOR_MULT_DOSStub_e126 {
  strings:
    $key_e126 = { b5 4e [2] c1 56 [2] 86 54 [2] c1 45 [2] 8f 49 [2] 83 43 [2] 94 48 [2] 8f 06 [2] b2 }

  condition:
    any of them
}