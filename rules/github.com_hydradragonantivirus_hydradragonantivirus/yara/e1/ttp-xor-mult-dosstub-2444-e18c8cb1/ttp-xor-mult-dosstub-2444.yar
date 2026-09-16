rule TTP_XOR_MULT_DOSStub_2444 {
  strings:
    $key_2444 = { 70 2c [2] 04 34 [2] 43 36 [2] 04 27 [2] 4a 2b [2] 46 21 [2] 51 2a [2] 4a 64 [2] 77 }

  condition:
    any of them
}