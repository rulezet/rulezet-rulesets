rule TTP_XOR_MULT_DOSStub_e2e6 {
  strings:
    $key_e2e6 = { b6 8e [2] c2 96 [2] 85 94 [2] c2 85 [2] 8c 89 [2] 80 83 [2] 97 88 [2] 8c c6 [2] b1 }

  condition:
    any of them
}