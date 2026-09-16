rule TTP_XOR_MULT_DOSStub_c425 {
  strings:
    $key_c425 = { 90 4d [2] e4 55 [2] a3 57 [2] e4 46 [2] aa 4a [2] a6 40 [2] b1 4b [2] aa 05 [2] 97 }

  condition:
    any of them
}