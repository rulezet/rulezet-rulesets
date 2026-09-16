rule TTP_XOR_MULT_DOSStub_fc73 {
  strings:
    $key_fc73 = { a8 1b [2] dc 03 [2] 9b 01 [2] dc 10 [2] 92 1c [2] 9e 16 [2] 89 1d [2] 92 53 [2] af }

  condition:
    any of them
}