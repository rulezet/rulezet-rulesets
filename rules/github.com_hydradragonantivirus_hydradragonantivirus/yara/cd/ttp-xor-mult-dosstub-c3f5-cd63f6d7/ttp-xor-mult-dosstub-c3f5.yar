rule TTP_XOR_MULT_DOSStub_c3f5 {
  strings:
    $key_c3f5 = { 97 9d [2] e3 85 [2] a4 87 [2] e3 96 [2] ad 9a [2] a1 90 [2] b6 9b [2] ad d5 [2] 90 }

  condition:
    any of them
}