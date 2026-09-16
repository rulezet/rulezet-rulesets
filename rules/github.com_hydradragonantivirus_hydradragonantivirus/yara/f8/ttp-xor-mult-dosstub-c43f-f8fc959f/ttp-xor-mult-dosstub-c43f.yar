rule TTP_XOR_MULT_DOSStub_c43f {
  strings:
    $key_c43f = { 90 57 [2] e4 4f [2] a3 4d [2] e4 5c [2] aa 50 [2] a6 5a [2] b1 51 [2] aa 1f [2] 97 }

  condition:
    any of them
}