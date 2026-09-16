rule TTP_XOR_MULT_DOSStub_e893 {
  strings:
    $key_e893 = { bc fb [2] c8 e3 [2] 8f e1 [2] c8 f0 [2] 86 fc [2] 8a f6 [2] 9d fd [2] 86 b3 [2] bb }

  condition:
    any of them
}