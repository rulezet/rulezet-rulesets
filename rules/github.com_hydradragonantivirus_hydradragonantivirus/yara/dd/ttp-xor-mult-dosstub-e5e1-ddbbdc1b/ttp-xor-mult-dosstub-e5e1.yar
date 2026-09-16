rule TTP_XOR_MULT_DOSStub_e5e1 {
  strings:
    $key_e5e1 = { b1 89 [2] c5 91 [2] 82 93 [2] c5 82 [2] 8b 8e [2] 87 84 [2] 90 8f [2] 8b c1 [2] b6 }

  condition:
    any of them
}