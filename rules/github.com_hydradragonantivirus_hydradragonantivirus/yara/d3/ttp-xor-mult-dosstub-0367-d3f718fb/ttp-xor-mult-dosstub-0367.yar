rule TTP_XOR_MULT_DOSStub_0367 {
  strings:
    $key_0367 = { 57 0f [2] 23 17 [2] 64 15 [2] 23 04 [2] 6d 08 [2] 61 02 [2] 76 09 [2] 6d 47 [2] 50 }

  condition:
    any of them
}