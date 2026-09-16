rule TTP_XOR_MULT_DOSStub_fce7 {
  strings:
    $key_fce7 = { a8 8f [2] dc 97 [2] 9b 95 [2] dc 84 [2] 92 88 [2] 9e 82 [2] 89 89 [2] 92 c7 [2] af }

  condition:
    any of them
}