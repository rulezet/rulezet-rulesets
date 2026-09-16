rule TTP_XOR_MULT_DOSStub_7228 {
  strings:
    $key_7228 = { 26 40 [2] 52 58 [2] 15 5a [2] 52 4b [2] 1c 47 [2] 10 4d [2] 07 46 [2] 1c 08 [2] 21 }

  condition:
    any of them
}