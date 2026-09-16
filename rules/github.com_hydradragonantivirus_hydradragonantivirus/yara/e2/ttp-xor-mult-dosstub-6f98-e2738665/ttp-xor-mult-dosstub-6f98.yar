rule TTP_XOR_MULT_DOSStub_6f98 {
  strings:
    $key_6f98 = { 3b f0 [2] 4f e8 [2] 08 ea [2] 4f fb [2] 01 f7 [2] 0d fd [2] 1a f6 [2] 01 b8 [2] 3c }

  condition:
    any of them
}