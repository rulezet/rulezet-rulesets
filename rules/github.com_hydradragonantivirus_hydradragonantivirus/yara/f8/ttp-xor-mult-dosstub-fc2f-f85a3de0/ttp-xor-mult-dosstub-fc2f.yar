rule TTP_XOR_MULT_DOSStub_fc2f {
  strings:
    $key_fc2f = { a8 47 [2] dc 5f [2] 9b 5d [2] dc 4c [2] 92 40 [2] 9e 4a [2] 89 41 [2] 92 0f [2] af }

  condition:
    any of them
}