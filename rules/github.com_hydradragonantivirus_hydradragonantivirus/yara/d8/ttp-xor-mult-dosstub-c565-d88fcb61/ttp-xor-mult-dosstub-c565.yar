rule TTP_XOR_MULT_DOSStub_c565 {
  strings:
    $key_c565 = { 91 0d [2] e5 15 [2] a2 17 [2] e5 06 [2] ab 0a [2] a7 00 [2] b0 0b [2] ab 45 [2] 96 }

  condition:
    any of them
}