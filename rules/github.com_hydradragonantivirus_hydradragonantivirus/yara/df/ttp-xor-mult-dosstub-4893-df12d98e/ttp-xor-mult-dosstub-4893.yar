rule TTP_XOR_MULT_DOSStub_4893 {
  strings:
    $key_4893 = { 1c fb [2] 68 e3 [2] 2f e1 [2] 68 f0 [2] 26 fc [2] 2a f6 [2] 3d fd [2] 26 b3 [2] 1b }

  condition:
    any of them
}