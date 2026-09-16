rule TTP_XOR_MULT_DOSStub_c5f8 {
  strings:
    $key_c5f8 = { 91 90 [2] e5 88 [2] a2 8a [2] e5 9b [2] ab 97 [2] a7 9d [2] b0 96 [2] ab d8 [2] 96 }

  condition:
    any of them
}