rule TTP_XOR_MULT_DOSStub_bb35 {
  strings:
    $key_bb35 = { ef 5d [2] 9b 45 [2] dc 47 [2] 9b 56 [2] d5 5a [2] d9 50 [2] ce 5b [2] d5 15 [2] e8 }

  condition:
    any of them
}