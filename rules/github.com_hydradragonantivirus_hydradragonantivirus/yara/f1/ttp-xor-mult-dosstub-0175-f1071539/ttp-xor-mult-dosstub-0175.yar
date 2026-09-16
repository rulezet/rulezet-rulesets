rule TTP_XOR_MULT_DOSStub_0175 {
  strings:
    $key_0175 = { 55 1d [2] 21 05 [2] 66 07 [2] 21 16 [2] 6f 1a [2] 63 10 [2] 74 1b [2] 6f 55 [2] 52 }

  condition:
    any of them
}