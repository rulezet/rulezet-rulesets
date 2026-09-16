rule TTP_XOR_MULT_DOSStub_bb57 {
  strings:
    $key_bb57 = { ef 3f [2] 9b 27 [2] dc 25 [2] 9b 34 [2] d5 38 [2] d9 32 [2] ce 39 [2] d5 77 [2] e8 }

  condition:
    any of them
}