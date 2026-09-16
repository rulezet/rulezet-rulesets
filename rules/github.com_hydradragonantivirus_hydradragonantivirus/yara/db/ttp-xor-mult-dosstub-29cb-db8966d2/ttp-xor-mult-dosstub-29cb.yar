rule TTP_XOR_MULT_DOSStub_29cb {
  strings:
    $key_29cb = { 7d a3 [2] 09 bb [2] 4e b9 [2] 09 a8 [2] 47 a4 [2] 4b ae [2] 5c a5 [2] 47 eb [2] 7a }

  condition:
    any of them
}