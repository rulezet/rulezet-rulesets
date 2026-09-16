rule TTP_XOR_MULT_DOSStub_19cb {
  strings:
    $key_19cb = { 4d a3 [2] 39 bb [2] 7e b9 [2] 39 a8 [2] 77 a4 [2] 7b ae [2] 6c a5 [2] 77 eb [2] 4a }

  condition:
    any of them
}