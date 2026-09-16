rule TTP_XOR_MULT_DOSStub_c571 {
  strings:
    $key_c571 = { 91 19 [2] e5 01 [2] a2 03 [2] e5 12 [2] ab 1e [2] a7 14 [2] b0 1f [2] ab 51 [2] 96 }

  condition:
    any of them
}