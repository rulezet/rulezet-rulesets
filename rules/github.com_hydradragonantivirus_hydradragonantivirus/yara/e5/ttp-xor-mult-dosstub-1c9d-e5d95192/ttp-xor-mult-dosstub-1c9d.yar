rule TTP_XOR_MULT_DOSStub_1c9d {
  strings:
    $key_1c9d = { 48 f5 [2] 3c ed [2] 7b ef [2] 3c fe [2] 72 f2 [2] 7e f8 [2] 69 f3 [2] 72 bd [2] 4f }

  condition:
    any of them
}