rule TTP_XOR_MULT_DOSStub_6aab {
  strings:
    $key_6aab = { 3e c3 [2] 4a db [2] 0d d9 [2] 4a c8 [2] 04 c4 [2] 08 ce [2] 1f c5 [2] 04 8b [2] 39 }

  condition:
    any of them
}