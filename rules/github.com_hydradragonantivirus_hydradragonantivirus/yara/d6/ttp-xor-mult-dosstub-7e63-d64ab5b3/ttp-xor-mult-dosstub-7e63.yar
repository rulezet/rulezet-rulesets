rule TTP_XOR_MULT_DOSStub_7e63 {
  strings:
    $key_7e63 = { 2a 0b [2] 5e 13 [2] 19 11 [2] 5e 00 [2] 10 0c [2] 1c 06 [2] 0b 0d [2] 10 43 [2] 2d }

  condition:
    any of them
}