rule TTP_XOR_MULT_DOSStub_c5e5 {
  strings:
    $key_c5e5 = { 91 8d [2] e5 95 [2] a2 97 [2] e5 86 [2] ab 8a [2] a7 80 [2] b0 8b [2] ab c5 [2] 96 }

  condition:
    any of them
}