rule TTP_XOR_MULT_DOSStub_c5f5 {
  strings:
    $key_c5f5 = { 91 9d [2] e5 85 [2] a2 87 [2] e5 96 [2] ab 9a [2] a7 90 [2] b0 9b [2] ab d5 [2] 96 }

  condition:
    any of them
}