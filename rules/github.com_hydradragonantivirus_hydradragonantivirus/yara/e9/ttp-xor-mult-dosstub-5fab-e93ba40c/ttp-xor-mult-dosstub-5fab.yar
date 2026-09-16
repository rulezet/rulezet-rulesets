rule TTP_XOR_MULT_DOSStub_5fab {
  strings:
    $key_5fab = { 0b c3 [2] 7f db [2] 38 d9 [2] 7f c8 [2] 31 c4 [2] 3d ce [2] 2a c5 [2] 31 8b [2] 0c }

  condition:
    any of them
}