rule TTP_XOR_MULT_DOSStub_bb70 {
  strings:
    $key_bb70 = { ef 18 [2] 9b 00 [2] dc 02 [2] 9b 13 [2] d5 1f [2] d9 15 [2] ce 1e [2] d5 50 [2] e8 }

  condition:
    any of them
}