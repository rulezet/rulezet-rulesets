rule TTP_XOR_MULT_DOSStub_c03f {
  strings:
    $key_c03f = { 94 57 [2] e0 4f [2] a7 4d [2] e0 5c [2] ae 50 [2] a2 5a [2] b5 51 [2] ae 1f [2] 93 }

  condition:
    any of them
}