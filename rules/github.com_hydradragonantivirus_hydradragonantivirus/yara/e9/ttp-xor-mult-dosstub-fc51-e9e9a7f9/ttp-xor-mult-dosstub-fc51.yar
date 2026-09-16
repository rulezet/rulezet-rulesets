rule TTP_XOR_MULT_DOSStub_fc51 {
  strings:
    $key_fc51 = { a8 39 [2] dc 21 [2] 9b 23 [2] dc 32 [2] 92 3e [2] 9e 34 [2] 89 3f [2] 92 71 [2] af }

  condition:
    any of them
}