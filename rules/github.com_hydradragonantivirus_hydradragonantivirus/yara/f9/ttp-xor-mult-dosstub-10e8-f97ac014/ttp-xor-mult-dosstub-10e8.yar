rule TTP_XOR_MULT_DOSStub_10e8 {
  strings:
    $key_10e8 = { 44 80 [2] 30 98 [2] 77 9a [2] 30 8b [2] 7e 87 [2] 72 8d [2] 65 86 [2] 7e c8 [2] 43 }

  condition:
    any of them
}