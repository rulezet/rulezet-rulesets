rule TTP_XOR_MULT_DOSStub_5b93 {
  strings:
    $key_5b93 = { 0f fb [2] 7b e3 [2] 3c e1 [2] 7b f0 [2] 35 fc [2] 39 f6 [2] 2e fd [2] 35 b3 [2] 08 }

  condition:
    any of them
}