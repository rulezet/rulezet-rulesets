rule TTP_XOR_MULT_DOSStub_5762 {
  strings:
    $key_5762 = { 03 0a [2] 77 12 [2] 30 10 [2] 77 01 [2] 39 0d [2] 35 07 [2] 22 0c [2] 39 42 [2] 04 }

  condition:
    any of them
}