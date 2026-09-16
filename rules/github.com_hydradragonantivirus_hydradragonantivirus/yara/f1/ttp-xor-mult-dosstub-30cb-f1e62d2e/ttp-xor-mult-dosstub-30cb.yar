rule TTP_XOR_MULT_DOSStub_30cb {
  strings:
    $key_30cb = { 64 a3 [2] 10 bb [2] 57 b9 [2] 10 a8 [2] 5e a4 [2] 52 ae [2] 45 a5 [2] 5e eb [2] 63 }

  condition:
    any of them
}