rule TTP_XOR_MULT_DOSStub_c353 {
  strings:
    $key_c353 = { 97 3b [2] e3 23 [2] a4 21 [2] e3 30 [2] ad 3c [2] a1 36 [2] b6 3d [2] ad 73 [2] 90 }

  condition:
    any of them
}