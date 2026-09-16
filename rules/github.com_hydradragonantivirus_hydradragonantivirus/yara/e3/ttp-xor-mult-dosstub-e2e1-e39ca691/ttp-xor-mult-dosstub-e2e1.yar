rule TTP_XOR_MULT_DOSStub_e2e1 {
  strings:
    $key_e2e1 = { b6 89 [2] c2 91 [2] 85 93 [2] c2 82 [2] 8c 8e [2] 80 84 [2] 97 8f [2] 8c c1 [2] b1 }

  condition:
    any of them
}