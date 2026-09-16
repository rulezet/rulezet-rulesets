rule TTP_XOR_MULT_DOSStub_02cb {
  strings:
    $key_02cb = { 56 a3 [2] 22 bb [2] 65 b9 [2] 22 a8 [2] 6c a4 [2] 60 ae [2] 77 a5 [2] 6c eb [2] 51 }

  condition:
    any of them
}