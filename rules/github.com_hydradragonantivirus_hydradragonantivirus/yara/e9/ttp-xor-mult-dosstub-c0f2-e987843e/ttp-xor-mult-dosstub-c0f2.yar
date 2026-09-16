rule TTP_XOR_MULT_DOSStub_c0f2 {
  strings:
    $key_c0f2 = { 94 9a [2] e0 82 [2] a7 80 [2] e0 91 [2] ae 9d [2] a2 97 [2] b5 9c [2] ae d2 [2] 93 }

  condition:
    any of them
}