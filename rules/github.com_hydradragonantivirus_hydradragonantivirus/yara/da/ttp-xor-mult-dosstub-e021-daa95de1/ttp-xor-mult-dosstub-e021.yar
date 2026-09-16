rule TTP_XOR_MULT_DOSStub_e021 {
  strings:
    $key_e021 = { b4 49 [2] c0 51 [2] 87 53 [2] c0 42 [2] 8e 4e [2] 82 44 [2] 95 4f [2] 8e 01 [2] b3 }

  condition:
    any of them
}