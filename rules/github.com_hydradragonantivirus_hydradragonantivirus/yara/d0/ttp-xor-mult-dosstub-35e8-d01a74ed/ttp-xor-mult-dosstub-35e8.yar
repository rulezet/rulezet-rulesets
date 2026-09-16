rule TTP_XOR_MULT_DOSStub_35e8 {
  strings:
    $key_35e8 = { 61 80 [2] 15 98 [2] 52 9a [2] 15 8b [2] 5b 87 [2] 57 8d [2] 40 86 [2] 5b c8 [2] 66 }

  condition:
    any of them
}