rule TTP_XOR_MULT_DOSStub_c107 {
  strings:
    $key_c107 = { 95 6f [2] e1 77 [2] a6 75 [2] e1 64 [2] af 68 [2] a3 62 [2] b4 69 [2] af 27 [2] 92 }

  condition:
    any of them
}