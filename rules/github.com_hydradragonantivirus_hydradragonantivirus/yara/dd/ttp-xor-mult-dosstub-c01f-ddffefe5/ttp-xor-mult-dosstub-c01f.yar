rule TTP_XOR_MULT_DOSStub_c01f {
  strings:
    $key_c01f = { 94 77 [2] e0 6f [2] a7 6d [2] e0 7c [2] ae 70 [2] a2 7a [2] b5 71 [2] ae 3f [2] 93 }

  condition:
    any of them
}