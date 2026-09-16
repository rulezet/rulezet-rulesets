rule TTP_XOR_MULT_DOSStub_fc12 {
  strings:
    $key_fc12 = { a8 7a [2] dc 62 [2] 9b 60 [2] dc 71 [2] 92 7d [2] 9e 77 [2] 89 7c [2] 92 32 [2] af }

  condition:
    any of them
}