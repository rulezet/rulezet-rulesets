rule TTP_XOR_MULT_DOSStub_7766 {
  strings:
    $key_7766 = { 23 0e [2] 57 16 [2] 10 14 [2] 57 05 [2] 19 09 [2] 15 03 [2] 02 08 [2] 19 46 [2] 24 }

  condition:
    any of them
}