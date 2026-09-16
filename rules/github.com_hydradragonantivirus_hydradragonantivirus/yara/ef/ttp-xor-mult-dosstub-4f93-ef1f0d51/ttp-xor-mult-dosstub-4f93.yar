rule TTP_XOR_MULT_DOSStub_4f93 {
  strings:
    $key_4f93 = { 1b fb [2] 6f e3 [2] 28 e1 [2] 6f f0 [2] 21 fc [2] 2d f6 [2] 3a fd [2] 21 b3 [2] 1c }

  condition:
    any of them
}