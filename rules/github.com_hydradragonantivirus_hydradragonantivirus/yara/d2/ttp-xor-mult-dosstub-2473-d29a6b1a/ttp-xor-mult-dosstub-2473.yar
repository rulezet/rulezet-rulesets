rule TTP_XOR_MULT_DOSStub_2473 {
  strings:
    $key_2473 = { 70 1b [2] 04 03 [2] 43 01 [2] 04 10 [2] 4a 1c [2] 46 16 [2] 51 1d [2] 4a 53 [2] 77 }

  condition:
    any of them
}