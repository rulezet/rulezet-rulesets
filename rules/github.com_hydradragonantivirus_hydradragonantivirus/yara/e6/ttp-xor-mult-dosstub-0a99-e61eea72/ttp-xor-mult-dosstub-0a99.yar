rule TTP_XOR_MULT_DOSStub_0a99 {
  strings:
    $key_0a99 = { 5e f1 [2] 2a e9 [2] 6d eb [2] 2a fa [2] 64 f6 [2] 68 fc [2] 7f f7 [2] 64 b9 [2] 59 }

  condition:
    any of them
}