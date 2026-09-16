rule TTP_XOR_MULT_DOSStub_519b {
  strings:
    $key_519b = { 05 f3 [2] 71 eb [2] 36 e9 [2] 71 f8 [2] 3f f4 [2] 33 fe [2] 24 f5 [2] 3f bb [2] 02 }

  condition:
    any of them
}