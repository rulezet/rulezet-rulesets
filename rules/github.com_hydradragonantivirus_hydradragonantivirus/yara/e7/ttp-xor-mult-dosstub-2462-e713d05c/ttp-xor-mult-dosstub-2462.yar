rule TTP_XOR_MULT_DOSStub_2462 {
  strings:
    $key_2462 = { 70 0a [2] 04 12 [2] 43 10 [2] 04 01 [2] 4a 0d [2] 46 07 [2] 51 0c [2] 4a 42 [2] 77 }

  condition:
    any of them
}