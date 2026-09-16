rule TTP_XOR_MULT_DOSStub_36c5 {
  strings:
    $key_36c5 = { 62 ad [2] 16 b5 [2] 51 b7 [2] 16 a6 [2] 58 aa [2] 54 a0 [2] 43 ab [2] 58 e5 [2] 65 }

  condition:
    any of them
}