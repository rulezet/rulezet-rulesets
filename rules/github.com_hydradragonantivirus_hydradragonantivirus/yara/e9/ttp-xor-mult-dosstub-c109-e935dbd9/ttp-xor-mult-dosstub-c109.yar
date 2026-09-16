rule TTP_XOR_MULT_DOSStub_c109 {
  strings:
    $key_c109 = { 95 61 [2] e1 79 [2] a6 7b [2] e1 6a [2] af 66 [2] a3 6c [2] b4 67 [2] af 29 [2] 92 }

  condition:
    any of them
}