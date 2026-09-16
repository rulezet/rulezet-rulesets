rule TTP_XOR_MULT_DOSStub_fce4 {
  strings:
    $key_fce4 = { a8 8c [2] dc 94 [2] 9b 96 [2] dc 87 [2] 92 8b [2] 9e 81 [2] 89 8a [2] 92 c4 [2] af }

  condition:
    any of them
}