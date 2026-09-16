rule TTP_XOR_MULT_DOSStub_3b61 {
  strings:
    $key_3b61 = { 6f 09 [2] 1b 11 [2] 5c 13 [2] 1b 02 [2] 55 0e [2] 59 04 [2] 4e 0f [2] 55 41 [2] 68 }

  condition:
    any of them
}