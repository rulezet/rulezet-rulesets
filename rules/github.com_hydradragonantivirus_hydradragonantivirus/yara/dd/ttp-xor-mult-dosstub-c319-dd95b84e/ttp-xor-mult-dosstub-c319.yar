rule TTP_XOR_MULT_DOSStub_c319 {
  strings:
    $key_c319 = { 97 71 [2] e3 69 [2] a4 6b [2] e3 7a [2] ad 76 [2] a1 7c [2] b6 77 [2] ad 39 [2] 90 }

  condition:
    any of them
}