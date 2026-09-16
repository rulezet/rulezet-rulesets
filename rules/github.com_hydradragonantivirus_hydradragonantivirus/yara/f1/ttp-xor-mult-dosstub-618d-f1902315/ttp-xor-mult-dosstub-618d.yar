rule TTP_XOR_MULT_DOSStub_618d {
  strings:
    $key_618d = { 35 e5 [2] 41 fd [2] 06 ff [2] 41 ee [2] 0f e2 [2] 03 e8 [2] 14 e3 [2] 0f ad [2] 32 }

  condition:
    any of them
}