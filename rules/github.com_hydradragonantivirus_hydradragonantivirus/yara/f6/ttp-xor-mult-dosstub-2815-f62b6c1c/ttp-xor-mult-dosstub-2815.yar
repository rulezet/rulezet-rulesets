rule TTP_XOR_MULT_DOSStub_2815 {
  strings:
    $key_2815 = { 7c 7d [2] 08 65 [2] 4f 67 [2] 08 76 [2] 46 7a [2] 4a 70 [2] 5d 7b [2] 46 35 [2] 7b }

  condition:
    any of them
}