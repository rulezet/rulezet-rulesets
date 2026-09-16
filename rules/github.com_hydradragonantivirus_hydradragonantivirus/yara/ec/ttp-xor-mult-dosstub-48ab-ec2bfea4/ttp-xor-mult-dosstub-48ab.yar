rule TTP_XOR_MULT_DOSStub_48ab {
  strings:
    $key_48ab = { 1c c3 [2] 68 db [2] 2f d9 [2] 68 c8 [2] 26 c4 [2] 2a ce [2] 3d c5 [2] 26 8b [2] 1b }

  condition:
    any of them
}