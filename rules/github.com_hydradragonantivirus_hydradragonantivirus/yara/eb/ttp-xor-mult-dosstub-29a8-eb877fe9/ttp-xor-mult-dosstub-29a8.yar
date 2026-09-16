rule TTP_XOR_MULT_DOSStub_29a8 {
  strings:
    $key_29a8 = { 7d c0 [2] 09 d8 [2] 4e da [2] 09 cb [2] 47 c7 [2] 4b cd [2] 5c c6 [2] 47 88 [2] 7a }

  condition:
    any of them
}