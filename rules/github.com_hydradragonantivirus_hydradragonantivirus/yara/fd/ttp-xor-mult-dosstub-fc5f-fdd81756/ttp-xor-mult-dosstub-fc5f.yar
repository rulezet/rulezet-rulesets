rule TTP_XOR_MULT_DOSStub_fc5f {
  strings:
    $key_fc5f = { a8 37 [2] dc 2f [2] 9b 2d [2] dc 3c [2] 92 30 [2] 9e 3a [2] 89 31 [2] 92 7f [2] af }

  condition:
    any of them
}