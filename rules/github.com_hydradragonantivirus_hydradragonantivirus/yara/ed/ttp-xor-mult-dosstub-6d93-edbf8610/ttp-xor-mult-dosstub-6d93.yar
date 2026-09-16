rule TTP_XOR_MULT_DOSStub_6d93 {
  strings:
    $key_6d93 = { 39 fb [2] 4d e3 [2] 0a e1 [2] 4d f0 [2] 03 fc [2] 0f f6 [2] 18 fd [2] 03 b3 [2] 3e }

  condition:
    any of them
}