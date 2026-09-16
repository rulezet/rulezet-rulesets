rule TTP_XOR_MULT_DOSStub_0845 {
  strings:
    $key_0845 = { 5c 2d [2] 28 35 [2] 6f 37 [2] 28 26 [2] 66 2a [2] 6a 20 [2] 7d 2b [2] 66 65 [2] 5b }

  condition:
    any of them
}