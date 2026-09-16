rule TTP_XOR_MULT_DOSStub_bbf5 {
  strings:
    $key_bbf5 = { ef 9d [2] 9b 85 [2] dc 87 [2] 9b 96 [2] d5 9a [2] d9 90 [2] ce 9b [2] d5 d5 [2] e8 }

  condition:
    any of them
}