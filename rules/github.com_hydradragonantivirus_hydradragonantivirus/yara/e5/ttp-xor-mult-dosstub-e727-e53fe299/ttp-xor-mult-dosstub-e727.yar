rule TTP_XOR_MULT_DOSStub_e727 {
  strings:
    $key_e727 = { b3 4f [2] c7 57 [2] 80 55 [2] c7 44 [2] 89 48 [2] 85 42 [2] 92 49 [2] 89 07 [2] b4 }

  condition:
    any of them
}