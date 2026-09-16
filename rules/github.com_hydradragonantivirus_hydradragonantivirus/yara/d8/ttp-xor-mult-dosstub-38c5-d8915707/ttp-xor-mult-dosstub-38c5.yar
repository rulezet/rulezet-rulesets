rule TTP_XOR_MULT_DOSStub_38c5 {
  strings:
    $key_38c5 = { 6c ad [2] 18 b5 [2] 5f b7 [2] 18 a6 [2] 56 aa [2] 5a a0 [2] 4d ab [2] 56 e5 [2] 6b }

  condition:
    any of them
}