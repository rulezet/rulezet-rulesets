rule TTP_XOR_MULT_DOSStub_5fce {
  strings:
    $key_5fce = { 0b a6 [2] 7f be [2] 38 bc [2] 7f ad [2] 31 a1 [2] 3d ab [2] 2a a0 [2] 31 ee [2] 0c }

  condition:
    any of them
}