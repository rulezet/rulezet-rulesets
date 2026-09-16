rule TTP_XOR_MULT_DOSStub_6a66 {
  strings:
    $key_6a66 = { 3e 0e [2] 4a 16 [2] 0d 14 [2] 4a 05 [2] 04 09 [2] 08 03 [2] 1f 08 [2] 04 46 [2] 39 }

  condition:
    any of them
}