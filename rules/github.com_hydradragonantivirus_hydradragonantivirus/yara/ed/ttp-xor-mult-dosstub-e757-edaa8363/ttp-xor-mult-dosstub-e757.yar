rule TTP_XOR_MULT_DOSStub_e757 {
  strings:
    $key_e757 = { b3 3f [2] c7 27 [2] 80 25 [2] c7 34 [2] 89 38 [2] 85 32 [2] 92 39 [2] 89 77 [2] b4 }

  condition:
    any of them
}