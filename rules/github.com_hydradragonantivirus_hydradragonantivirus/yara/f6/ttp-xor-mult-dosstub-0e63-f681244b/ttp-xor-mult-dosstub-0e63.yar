rule TTP_XOR_MULT_DOSStub_0e63 {
  strings:
    $key_0e63 = { 5a 0b [2] 2e 13 [2] 69 11 [2] 2e 00 [2] 60 0c [2] 6c 06 [2] 7b 0d [2] 60 43 [2] 5d }

  condition:
    any of them
}