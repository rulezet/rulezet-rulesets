rule TTP_XOR_MULT_DOSStub_5c9d {
  strings:
    $key_5c9d = { 08 f5 [2] 7c ed [2] 3b ef [2] 7c fe [2] 32 f2 [2] 3e f8 [2] 29 f3 [2] 32 bd [2] 0f }

  condition:
    any of them
}