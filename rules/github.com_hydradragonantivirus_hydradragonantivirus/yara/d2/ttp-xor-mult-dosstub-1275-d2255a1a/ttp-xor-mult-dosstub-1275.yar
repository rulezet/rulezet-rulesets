rule TTP_XOR_MULT_DOSStub_1275 {
  strings:
    $key_1275 = { 46 1d [2] 32 05 [2] 75 07 [2] 32 16 [2] 7c 1a [2] 70 10 [2] 67 1b [2] 7c 55 [2] 41 }

  condition:
    any of them
}