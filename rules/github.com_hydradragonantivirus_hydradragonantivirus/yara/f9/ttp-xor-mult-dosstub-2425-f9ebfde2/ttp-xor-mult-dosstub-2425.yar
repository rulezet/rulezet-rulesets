rule TTP_XOR_MULT_DOSStub_2425 {
  strings:
    $key_2425 = { 70 4d [2] 04 55 [2] 43 57 [2] 04 46 [2] 4a 4a [2] 46 40 [2] 51 4b [2] 4a 05 [2] 77 }

  condition:
    any of them
}