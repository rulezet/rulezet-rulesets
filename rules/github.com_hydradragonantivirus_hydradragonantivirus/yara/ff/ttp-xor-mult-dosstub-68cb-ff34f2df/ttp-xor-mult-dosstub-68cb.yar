rule TTP_XOR_MULT_DOSStub_68cb {
  strings:
    $key_68cb = { 3c a3 [2] 48 bb [2] 0f b9 [2] 48 a8 [2] 06 a4 [2] 0a ae [2] 1d a5 [2] 06 eb [2] 3b }

  condition:
    any of them
}