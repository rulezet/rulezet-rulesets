rule TTP_XOR_MULT_DOSStub_3f98 {
  strings:
    $key_3f98 = { 6b f0 [2] 1f e8 [2] 58 ea [2] 1f fb [2] 51 f7 [2] 5d fd [2] 4a f6 [2] 51 b8 [2] 6c }

  condition:
    any of them
}