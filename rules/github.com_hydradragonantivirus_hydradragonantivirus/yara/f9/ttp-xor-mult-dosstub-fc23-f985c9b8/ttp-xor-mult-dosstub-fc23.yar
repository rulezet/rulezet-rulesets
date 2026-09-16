rule TTP_XOR_MULT_DOSStub_fc23 {
  strings:
    $key_fc23 = { a8 4b [2] dc 53 [2] 9b 51 [2] dc 40 [2] 92 4c [2] 9e 46 [2] 89 4d [2] 92 03 [2] af }

  condition:
    any of them
}