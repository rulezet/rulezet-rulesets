rule TTP_XOR_MULT_DOSStub_e121 {
  strings:
    $key_e121 = { b5 49 [2] c1 51 [2] 86 53 [2] c1 42 [2] 8f 4e [2] 83 44 [2] 94 4f [2] 8f 01 [2] b2 }

  condition:
    any of them
}