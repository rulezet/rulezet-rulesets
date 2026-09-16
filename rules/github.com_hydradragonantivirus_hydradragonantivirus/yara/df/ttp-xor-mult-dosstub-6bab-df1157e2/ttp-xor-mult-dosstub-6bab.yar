rule TTP_XOR_MULT_DOSStub_6bab {
  strings:
    $key_6bab = { 3f c3 [2] 4b db [2] 0c d9 [2] 4b c8 [2] 05 c4 [2] 09 ce [2] 1e c5 [2] 05 8b [2] 38 }

  condition:
    any of them
}