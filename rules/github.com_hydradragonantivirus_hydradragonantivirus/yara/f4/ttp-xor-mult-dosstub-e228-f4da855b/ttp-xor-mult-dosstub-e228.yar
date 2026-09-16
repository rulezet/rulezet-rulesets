rule TTP_XOR_MULT_DOSStub_e228 {
  strings:
    $key_e228 = { b6 40 [2] c2 58 [2] 85 5a [2] c2 4b [2] 8c 47 [2] 80 4d [2] 97 46 [2] 8c 08 [2] b1 }

  condition:
    any of them
}