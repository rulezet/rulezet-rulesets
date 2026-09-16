rule TTP_XOR_MULT_DOSStub_64c4 {
  strings:
    $key_64c4 = { 30 ac [2] 44 b4 [2] 03 b6 [2] 44 a7 [2] 0a ab [2] 06 a1 [2] 11 aa [2] 0a e4 [2] 37 }

  condition:
    any of them
}