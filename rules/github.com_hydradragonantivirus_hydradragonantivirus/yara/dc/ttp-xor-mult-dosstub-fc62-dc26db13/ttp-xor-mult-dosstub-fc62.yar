rule TTP_XOR_MULT_DOSStub_fc62 {
  strings:
    $key_fc62 = { a8 0a [2] dc 12 [2] 9b 10 [2] dc 01 [2] 92 0d [2] 9e 07 [2] 89 0c [2] 92 42 [2] af }

  condition:
    any of them
}