rule TTP_XOR_MULT_DOSStub_5dad {
  strings:
    $key_5dad = { 09 c5 [2] 7d dd [2] 3a df [2] 7d ce [2] 33 c2 [2] 3f c8 [2] 28 c3 [2] 33 8d [2] 0e }

  condition:
    any of them
}