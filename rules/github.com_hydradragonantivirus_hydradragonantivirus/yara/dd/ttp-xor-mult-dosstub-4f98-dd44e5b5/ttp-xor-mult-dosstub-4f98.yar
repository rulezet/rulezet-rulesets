rule TTP_XOR_MULT_DOSStub_4f98 {
  strings:
    $key_4f98 = { 1b f0 [2] 6f e8 [2] 28 ea [2] 6f fb [2] 21 f7 [2] 2d fd [2] 3a f6 [2] 21 b8 [2] 1c }

  condition:
    any of them
}