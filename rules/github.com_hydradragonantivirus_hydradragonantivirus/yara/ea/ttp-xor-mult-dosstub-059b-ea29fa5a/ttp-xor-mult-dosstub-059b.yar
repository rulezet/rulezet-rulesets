rule TTP_XOR_MULT_DOSStub_059b {
  strings:
    $key_059b = { 51 f3 [2] 25 eb [2] 62 e9 [2] 25 f8 [2] 6b f4 [2] 67 fe [2] 70 f5 [2] 6b bb [2] 56 }

  condition:
    any of them
}