rule TTP_XOR_MULT_DOSStub_bb34 {
  strings:
    $key_bb34 = { ef 5c [2] 9b 44 [2] dc 46 [2] 9b 57 [2] d5 5b [2] d9 51 [2] ce 5a [2] d5 14 [2] e8 }

  condition:
    any of them
}