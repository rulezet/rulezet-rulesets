rule TTP_XOR_MULT_DOSStub_fcfa {
  strings:
    $key_fcfa = { a8 92 [2] dc 8a [2] 9b 88 [2] dc 99 [2] 92 95 [2] 9e 9f [2] 89 94 [2] 92 da [2] af }

  condition:
    any of them
}