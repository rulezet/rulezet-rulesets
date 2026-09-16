rule TTP_XOR_MULT_DOSStub_18cb {
  strings:
    $key_18cb = { 4c a3 [2] 38 bb [2] 7f b9 [2] 38 a8 [2] 76 a4 [2] 7a ae [2] 6d a5 [2] 76 eb [2] 4b }

  condition:
    any of them
}