rule TTP_XOR_MULT_DOSStub_bb38 {
  strings:
    $key_bb38 = { ef 50 [2] 9b 48 [2] dc 4a [2] 9b 5b [2] d5 57 [2] d9 5d [2] ce 56 [2] d5 18 [2] e8 }

  condition:
    any of them
}