rule TTP_XOR_MULT_DOSStub_fe98 {
  strings:
    $key_fe98 = { aa f0 [2] de e8 [2] 99 ea [2] de fb [2] 90 f7 [2] 9c fd [2] 8b f6 [2] 90 b8 [2] ad }

  condition:
    any of them
}