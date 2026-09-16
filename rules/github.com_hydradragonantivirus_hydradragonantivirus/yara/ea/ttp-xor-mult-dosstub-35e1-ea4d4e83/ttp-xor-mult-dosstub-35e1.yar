rule TTP_XOR_MULT_DOSStub_35e1 {
  strings:
    $key_35e1 = { 61 89 [2] 15 91 [2] 52 93 [2] 15 82 [2] 5b 8e [2] 57 84 [2] 40 8f [2] 5b c1 [2] 66 }

  condition:
    any of them
}