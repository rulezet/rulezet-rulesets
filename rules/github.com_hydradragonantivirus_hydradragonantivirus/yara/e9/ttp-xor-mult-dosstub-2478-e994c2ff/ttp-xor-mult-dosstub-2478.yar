rule TTP_XOR_MULT_DOSStub_2478 {
  strings:
    $key_2478 = { 70 10 [2] 04 08 [2] 43 0a [2] 04 1b [2] 4a 17 [2] 46 1d [2] 51 16 [2] 4a 58 [2] 77 }

  condition:
    any of them
}