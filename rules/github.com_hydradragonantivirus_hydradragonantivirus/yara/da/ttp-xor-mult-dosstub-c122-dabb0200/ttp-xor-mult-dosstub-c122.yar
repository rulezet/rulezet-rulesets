rule TTP_XOR_MULT_DOSStub_c122 {
  strings:
    $key_c122 = { 95 4a [2] e1 52 [2] a6 50 [2] e1 41 [2] af 4d [2] a3 47 [2] b4 4c [2] af 02 [2] 92 }

  condition:
    any of them
}