rule TTP_XOR_MULT_DOSStub_c102 {
  strings:
    $key_c102 = { 95 6a [2] e1 72 [2] a6 70 [2] e1 61 [2] af 6d [2] a3 67 [2] b4 6c [2] af 22 [2] 92 }

  condition:
    any of them
}