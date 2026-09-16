rule TTP_XOR_MULT_DOSStub_c123 {
  strings:
    $key_c123 = { 95 4b [2] e1 53 [2] a6 51 [2] e1 40 [2] af 4c [2] a3 46 [2] b4 4d [2] af 03 [2] 92 }

  condition:
    any of them
}