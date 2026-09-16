rule TTP_XOR_MULT_DOSStub_c035 {
  strings:
    $key_c035 = { 94 5d [2] e0 45 [2] a7 47 [2] e0 56 [2] ae 5a [2] a2 50 [2] b5 5b [2] ae 15 [2] 93 }

  condition:
    any of them
}