rule TTP_XOR_MULT_DOSStub_5f93 {
  strings:
    $key_5f93 = { 0b fb [2] 7f e3 [2] 38 e1 [2] 7f f0 [2] 31 fc [2] 3d f6 [2] 2a fd [2] 31 b3 [2] 0c }

  condition:
    any of them
}