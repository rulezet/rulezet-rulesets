rule TTP_XOR_MULT_DOSStub_c527 {
  strings:
    $key_c527 = { 91 4f [2] e5 57 [2] a2 55 [2] e5 44 [2] ab 48 [2] a7 42 [2] b0 49 [2] ab 07 [2] 96 }

  condition:
    any of them
}