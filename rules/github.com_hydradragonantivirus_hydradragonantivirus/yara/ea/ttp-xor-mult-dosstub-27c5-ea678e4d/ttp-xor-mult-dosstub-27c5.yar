rule TTP_XOR_MULT_DOSStub_27c5 {
  strings:
    $key_27c5 = { 73 ad [2] 07 b5 [2] 40 b7 [2] 07 a6 [2] 49 aa [2] 45 a0 [2] 52 ab [2] 49 e5 [2] 74 }

  condition:
    any of them
}