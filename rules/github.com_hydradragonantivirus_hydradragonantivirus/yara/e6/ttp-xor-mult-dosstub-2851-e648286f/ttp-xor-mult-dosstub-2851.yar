rule TTP_XOR_MULT_DOSStub_2851 {
  strings:
    $key_2851 = { 7c 39 [2] 08 21 [2] 4f 23 [2] 08 32 [2] 46 3e [2] 4a 34 [2] 5d 3f [2] 46 71 [2] 7b }

  condition:
    any of them
}