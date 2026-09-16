rule TTP_XOR_MULT_DOSStub_c560 {
  strings:
    $key_c560 = { 91 08 [2] e5 10 [2] a2 12 [2] e5 03 [2] ab 0f [2] a7 05 [2] b0 0e [2] ab 40 [2] 96 }

  condition:
    any of them
}