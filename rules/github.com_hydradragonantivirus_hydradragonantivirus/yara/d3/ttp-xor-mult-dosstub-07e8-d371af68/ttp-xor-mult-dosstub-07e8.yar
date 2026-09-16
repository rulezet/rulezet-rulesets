rule TTP_XOR_MULT_DOSStub_07e8 {
  strings:
    $key_07e8 = { 53 80 [2] 27 98 [2] 60 9a [2] 27 8b [2] 69 87 [2] 65 8d [2] 72 86 [2] 69 c8 [2] 54 }

  condition:
    any of them
}