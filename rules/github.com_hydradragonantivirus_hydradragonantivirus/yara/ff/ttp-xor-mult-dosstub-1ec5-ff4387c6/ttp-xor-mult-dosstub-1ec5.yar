rule TTP_XOR_MULT_DOSStub_1ec5 {
  strings:
    $key_1ec5 = { 4a ad [2] 3e b5 [2] 79 b7 [2] 3e a6 [2] 70 aa [2] 7c a0 [2] 6b ab [2] 70 e5 [2] 4d }

  condition:
    any of them
}