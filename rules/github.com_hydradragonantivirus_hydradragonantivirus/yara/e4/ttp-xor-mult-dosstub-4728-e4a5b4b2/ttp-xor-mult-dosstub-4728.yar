rule TTP_XOR_MULT_DOSStub_4728 {
  strings:
    $key_4728 = { 13 40 [2] 67 58 [2] 20 5a [2] 67 4b [2] 29 47 [2] 25 4d [2] 32 46 [2] 29 08 [2] 14 }

  condition:
    any of them
}