rule TTP_XOR_MULT_DOSStub_29b9 {
  strings:
    $key_29b9 = { 7d d1 [2] 09 c9 [2] 4e cb [2] 09 da [2] 47 d6 [2] 4b dc [2] 5c d7 [2] 47 99 [2] 7a }

  condition:
    any of them
}