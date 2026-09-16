rule TTP_XOR_MULT_DOSStub_2525 {
  strings:
    $key_2525 = { 71 4d [2] 05 55 [2] 42 57 [2] 05 46 [2] 4b 4a [2] 47 40 [2] 50 4b [2] 4b 05 [2] 76 }

  condition:
    any of them
}