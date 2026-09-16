rule TTP_XOR_MULT_DOSStub_c73f {
  strings:
    $key_c73f = { 93 57 [2] e7 4f [2] a0 4d [2] e7 5c [2] a9 50 [2] a5 5a [2] b2 51 [2] a9 1f [2] 94 }

  condition:
    any of them
}