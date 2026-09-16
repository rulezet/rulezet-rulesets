rule TTP_XOR_MULT_DOSStub_fcfc {
  strings:
    $key_fcfc = { a8 94 [2] dc 8c [2] 9b 8e [2] dc 9f [2] 92 93 [2] 9e 99 [2] 89 92 [2] 92 dc [2] af }

  condition:
    any of them
}