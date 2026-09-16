rule TTP_XOR_MULT_DOSStub_5773 {
  strings:
    $key_5773 = { 03 1b [2] 77 03 [2] 30 01 [2] 77 10 [2] 39 1c [2] 35 16 [2] 22 1d [2] 39 53 [2] 04 }

  condition:
    any of them
}