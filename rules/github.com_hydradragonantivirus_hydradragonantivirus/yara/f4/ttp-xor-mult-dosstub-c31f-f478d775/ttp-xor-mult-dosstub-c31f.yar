rule TTP_XOR_MULT_DOSStub_c31f {
  strings:
    $key_c31f = { 97 77 [2] e3 6f [2] a4 6d [2] e3 7c [2] ad 70 [2] a1 7a [2] b6 71 [2] ad 3f [2] 90 }

  condition:
    any of them
}