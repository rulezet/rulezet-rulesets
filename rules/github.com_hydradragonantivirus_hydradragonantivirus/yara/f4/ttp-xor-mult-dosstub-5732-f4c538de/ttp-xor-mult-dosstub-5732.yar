rule TTP_XOR_MULT_DOSStub_5732 {
  strings:
    $key_5732 = { 03 5a [2] 77 42 [2] 30 40 [2] 77 51 [2] 39 5d [2] 35 57 [2] 22 5c [2] 39 12 [2] 04 }

  condition:
    any of them
}