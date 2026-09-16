rule TTP_XOR_MULT_DOSStub_c019 {
  strings:
    $key_c019 = { 94 71 [2] e0 69 [2] a7 6b [2] e0 7a [2] ae 76 [2] a2 7c [2] b5 77 [2] ae 39 [2] 93 }

  condition:
    any of them
}