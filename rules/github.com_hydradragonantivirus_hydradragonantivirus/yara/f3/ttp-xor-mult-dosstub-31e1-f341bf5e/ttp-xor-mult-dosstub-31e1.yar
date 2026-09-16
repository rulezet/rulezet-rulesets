rule TTP_XOR_MULT_DOSStub_31e1 {
  strings:
    $key_31e1 = { 65 89 [2] 11 91 [2] 56 93 [2] 11 82 [2] 5f 8e [2] 53 84 [2] 44 8f [2] 5f c1 [2] 62 }

  condition:
    any of them
}