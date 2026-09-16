rule TTP_XOR_MULT_DOSStub_0178 {
  strings:
    $key_0178 = { 55 10 [2] 21 08 [2] 66 0a [2] 21 1b [2] 6f 17 [2] 63 1d [2] 74 16 [2] 6f 58 [2] 52 }

  condition:
    any of them
}