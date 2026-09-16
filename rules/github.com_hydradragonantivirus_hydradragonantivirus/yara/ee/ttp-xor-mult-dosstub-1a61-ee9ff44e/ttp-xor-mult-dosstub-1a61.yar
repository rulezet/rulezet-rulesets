rule TTP_XOR_MULT_DOSStub_1a61 {
  strings:
    $key_1a61 = { 4e 09 [2] 3a 11 [2] 7d 13 [2] 3a 02 [2] 74 0e [2] 78 04 [2] 6f 0f [2] 74 41 [2] 49 }

  condition:
    any of them
}