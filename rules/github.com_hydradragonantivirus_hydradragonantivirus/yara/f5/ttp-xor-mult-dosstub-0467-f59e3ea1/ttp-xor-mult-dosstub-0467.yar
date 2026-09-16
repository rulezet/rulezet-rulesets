rule TTP_XOR_MULT_DOSStub_0467 {
  strings:
    $key_0467 = { 50 0f [2] 24 17 [2] 63 15 [2] 24 04 [2] 6a 08 [2] 66 02 [2] 71 09 [2] 6a 47 [2] 57 }

  condition:
    any of them
}