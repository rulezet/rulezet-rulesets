rule TTP_XOR_MULT_DOSStub_28e0 {
  strings:
    $key_28e0 = { 7c 88 [2] 08 90 [2] 4f 92 [2] 08 83 [2] 46 8f [2] 4a 85 [2] 5d 8e [2] 46 c0 [2] 7b }

  condition:
    any of them
}