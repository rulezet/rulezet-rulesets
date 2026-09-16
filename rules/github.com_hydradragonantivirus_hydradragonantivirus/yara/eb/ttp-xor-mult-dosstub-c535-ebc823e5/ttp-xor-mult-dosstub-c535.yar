rule TTP_XOR_MULT_DOSStub_c535 {
  strings:
    $key_c535 = { 91 5d [2] e5 45 [2] a2 47 [2] e5 56 [2] ab 5a [2] a7 50 [2] b0 5b [2] ab 15 [2] 96 }

  condition:
    any of them
}