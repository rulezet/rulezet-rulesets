rule TTP_XOR_MULT_DOSStub_7028 {
  strings:
    $key_7028 = { 24 40 [2] 50 58 [2] 17 5a [2] 50 4b [2] 1e 47 [2] 12 4d [2] 05 46 [2] 1e 08 [2] 23 }

  condition:
    any of them
}