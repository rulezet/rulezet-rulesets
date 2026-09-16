rule TTP_XOR_MULT_DOSStub_2b66 {
  strings:
    $key_2b66 = { 7f 0e [2] 0b 16 [2] 4c 14 [2] 0b 05 [2] 45 09 [2] 49 03 [2] 5e 08 [2] 45 46 [2] 78 }

  condition:
    any of them
}