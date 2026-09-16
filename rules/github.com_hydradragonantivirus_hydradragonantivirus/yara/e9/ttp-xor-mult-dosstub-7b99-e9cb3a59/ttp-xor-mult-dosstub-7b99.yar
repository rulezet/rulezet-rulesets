rule TTP_XOR_MULT_DOSStub_7b99 {
  strings:
    $key_7b99 = { 2f f1 [2] 5b e9 [2] 1c eb [2] 5b fa [2] 15 f6 [2] 19 fc [2] 0e f7 [2] 15 b9 [2] 28 }

  condition:
    any of them
}