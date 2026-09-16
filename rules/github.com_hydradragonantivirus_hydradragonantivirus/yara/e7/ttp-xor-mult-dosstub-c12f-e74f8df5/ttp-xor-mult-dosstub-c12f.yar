rule TTP_XOR_MULT_DOSStub_c12f {
  strings:
    $key_c12f = { 95 47 [2] e1 5f [2] a6 5d [2] e1 4c [2] af 40 [2] a3 4a [2] b4 41 [2] af 0f [2] 92 }

  condition:
    any of them
}