rule TTP_XOR_MULT_DOSStub_fc9c {
  strings:
    $key_fc9c = { a8 f4 [2] dc ec [2] 9b ee [2] dc ff [2] 92 f3 [2] 9e f9 [2] 89 f2 [2] 92 bc [2] af }

  condition:
    any of them
}