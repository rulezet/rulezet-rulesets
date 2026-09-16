rule TTP_XOR_MULT_DOSStub_bbf6 {
  strings:
    $key_bbf6 = { ef 9e [2] 9b 86 [2] dc 84 [2] 9b 95 [2] d5 99 [2] d9 93 [2] ce 98 [2] d5 d6 [2] e8 }

  condition:
    any of them
}