rule TTP_XOR_MULT_DOSStub_1976 {
  strings:
    $key_1976 = { 4d 1e [2] 39 06 [2] 7e 04 [2] 39 15 [2] 77 19 [2] 7b 13 [2] 6c 18 [2] 77 56 [2] 4a }

  condition:
    any of them
}