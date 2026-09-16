rule TTP_XOR_MULT_DOSStub_fcc8 {
  strings:
    $key_fcc8 = { a8 a0 [2] dc b8 [2] 9b ba [2] dc ab [2] 92 a7 [2] 9e ad [2] 89 a6 [2] 92 e8 [2] af }

  condition:
    any of them
}