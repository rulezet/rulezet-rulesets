rule TTP_XOR_MULT_DOSStub_fcf8 {
  strings:
    $key_fcf8 = { a8 90 [2] dc 88 [2] 9b 8a [2] dc 9b [2] 92 97 [2] 9e 9d [2] 89 96 [2] 92 d8 [2] af }

  condition:
    any of them
}