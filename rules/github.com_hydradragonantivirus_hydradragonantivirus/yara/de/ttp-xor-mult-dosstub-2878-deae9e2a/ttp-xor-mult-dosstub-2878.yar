rule TTP_XOR_MULT_DOSStub_2878 {
  strings:
    $key_2878 = { 7c 10 [2] 08 08 [2] 4f 0a [2] 08 1b [2] 46 17 [2] 4a 1d [2] 5d 16 [2] 46 58 [2] 7b }

  condition:
    any of them
}