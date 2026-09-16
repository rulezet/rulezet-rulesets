rule TTP_XOR_MULT_DOSStub_e215 {
  strings:
    $key_e215 = { b6 7d [2] c2 65 [2] 85 67 [2] c2 76 [2] 8c 7a [2] 80 70 [2] 97 7b [2] 8c 35 [2] b1 }

  condition:
    any of them
}