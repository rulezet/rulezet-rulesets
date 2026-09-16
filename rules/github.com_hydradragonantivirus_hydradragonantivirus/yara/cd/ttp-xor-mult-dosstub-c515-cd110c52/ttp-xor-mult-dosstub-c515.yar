rule TTP_XOR_MULT_DOSStub_c515 {
  strings:
    $key_c515 = { 91 7d [2] e5 65 [2] a2 67 [2] e5 76 [2] ab 7a [2] a7 70 [2] b0 7b [2] ab 35 [2] 96 }

  condition:
    any of them
}