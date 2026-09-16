rule TTP_XOR_MULT_DOSStub_bb44 {
  strings:
    $key_bb44 = { ef 2c [2] 9b 34 [2] dc 36 [2] 9b 27 [2] d5 2b [2] d9 21 [2] ce 2a [2] d5 64 [2] e8 }

  condition:
    any of them
}