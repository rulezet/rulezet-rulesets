rule TTP_XOR_MULT_DOSStub_1973 {
  strings:
    $key_1973 = { 4d 1b [2] 39 03 [2] 7e 01 [2] 39 10 [2] 77 1c [2] 7b 16 [2] 6c 1d [2] 77 53 [2] 4a }

  condition:
    any of them
}