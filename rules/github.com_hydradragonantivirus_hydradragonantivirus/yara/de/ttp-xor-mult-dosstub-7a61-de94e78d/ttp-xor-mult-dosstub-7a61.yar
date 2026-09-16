rule TTP_XOR_MULT_DOSStub_7a61 {
  strings:
    $key_7a61 = { 2e 09 [2] 5a 11 [2] 1d 13 [2] 5a 02 [2] 14 0e [2] 18 04 [2] 0f 0f [2] 14 41 [2] 29 }

  condition:
    any of them
}