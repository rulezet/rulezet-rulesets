rule TTP_XOR_MULT_DOSStub_3acc {
  strings:
    $key_3acc = { 6e a4 [2] 1a bc [2] 5d be [2] 1a af [2] 54 a3 [2] 58 a9 [2] 4f a2 [2] 54 ec [2] 69 }

  condition:
    any of them
}