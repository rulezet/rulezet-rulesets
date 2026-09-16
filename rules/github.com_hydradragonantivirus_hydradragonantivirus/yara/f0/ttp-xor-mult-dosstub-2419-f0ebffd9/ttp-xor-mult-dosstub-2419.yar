rule TTP_XOR_MULT_DOSStub_2419 {
  strings:
    $key_2419 = { 70 71 [2] 04 69 [2] 43 6b [2] 04 7a [2] 4a 76 [2] 46 7c [2] 51 77 [2] 4a 39 [2] 77 }

  condition:
    any of them
}