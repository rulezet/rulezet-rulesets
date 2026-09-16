rule TTP_XOR_MULT_DOSStub_c135 {
  strings:
    $key_c135 = { 95 5d [2] e1 45 [2] a6 47 [2] e1 56 [2] af 5a [2] a3 50 [2] b4 5b [2] af 15 [2] 92 }

  condition:
    any of them
}