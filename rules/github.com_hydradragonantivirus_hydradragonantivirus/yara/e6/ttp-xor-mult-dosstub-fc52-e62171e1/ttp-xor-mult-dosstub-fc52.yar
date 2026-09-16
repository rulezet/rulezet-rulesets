rule TTP_XOR_MULT_DOSStub_fc52 {
  strings:
    $key_fc52 = { a8 3a [2] dc 22 [2] 9b 20 [2] dc 31 [2] 92 3d [2] 9e 37 [2] 89 3c [2] 92 72 [2] af }

  condition:
    any of them
}