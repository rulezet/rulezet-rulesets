rule TTP_XOR_MULT_DOSStub_bb49 {
  strings:
    $key_bb49 = { ef 21 [2] 9b 39 [2] dc 3b [2] 9b 2a [2] d5 26 [2] d9 2c [2] ce 27 [2] d5 69 [2] e8 }

  condition:
    any of them
}