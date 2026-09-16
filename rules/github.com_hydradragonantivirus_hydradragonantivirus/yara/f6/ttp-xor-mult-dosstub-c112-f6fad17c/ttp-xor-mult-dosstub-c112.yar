rule TTP_XOR_MULT_DOSStub_c112 {
  strings:
    $key_c112 = { 95 7a [2] e1 62 [2] a6 60 [2] e1 71 [2] af 7d [2] a3 77 [2] b4 7c [2] af 32 [2] 92 }

  condition:
    any of them
}