rule TTP_XOR_MULT_DOSStub_0778 {
  strings:
    $key_0778 = { 53 10 [2] 27 08 [2] 60 0a [2] 27 1b [2] 69 17 [2] 65 1d [2] 72 16 [2] 69 58 [2] 54 }

  condition:
    any of them
}