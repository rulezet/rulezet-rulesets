rule TTP_XOR_MULT_DOSStub_4cd9 {
  strings:
    $key_4cd9 = { 18 b1 [2] 6c a9 [2] 2b ab [2] 6c ba [2] 22 b6 [2] 2e bc [2] 39 b7 [2] 22 f9 [2] 1f }

  condition:
    any of them
}