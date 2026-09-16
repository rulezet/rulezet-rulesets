rule TTP_XOR_MULT_DOSStub_47cb {
  strings:
    $key_47cb = { 13 a3 [2] 67 bb [2] 20 b9 [2] 67 a8 [2] 29 a4 [2] 25 ae [2] 32 a5 [2] 29 eb [2] 14 }

  condition:
    any of them
}