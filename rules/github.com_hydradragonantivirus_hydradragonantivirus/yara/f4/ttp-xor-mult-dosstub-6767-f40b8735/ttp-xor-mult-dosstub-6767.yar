rule TTP_XOR_MULT_DOSStub_6767 {
  strings:
    $key_6767 = { 33 0f [2] 47 17 [2] 00 15 [2] 47 04 [2] 09 08 [2] 05 02 [2] 12 09 [2] 09 47 [2] 34 }

  condition:
    any of them
}