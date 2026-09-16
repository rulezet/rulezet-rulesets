rule TTP_XOR_MULT_DOSStub_c171 {
  strings:
    $key_c171 = { 95 19 [2] e1 01 [2] a6 03 [2] e1 12 [2] af 1e [2] a3 14 [2] b4 1f [2] af 51 [2] 92 }

  condition:
    any of them
}