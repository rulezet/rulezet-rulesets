rule TTP_XOR_MULT_DOSStub_c304 {
  strings:
    $key_c304 = { 97 6c [2] e3 74 [2] a4 76 [2] e3 67 [2] ad 6b [2] a1 61 [2] b6 6a [2] ad 24 [2] 90 }

  condition:
    any of them
}