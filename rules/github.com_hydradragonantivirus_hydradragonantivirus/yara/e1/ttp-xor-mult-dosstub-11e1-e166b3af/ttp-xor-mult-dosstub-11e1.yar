rule TTP_XOR_MULT_DOSStub_11e1 {
  strings:
    $key_11e1 = { 45 89 [2] 31 91 [2] 76 93 [2] 31 82 [2] 7f 8e [2] 73 84 [2] 64 8f [2] 7f c1 [2] 42 }

  condition:
    any of them
}