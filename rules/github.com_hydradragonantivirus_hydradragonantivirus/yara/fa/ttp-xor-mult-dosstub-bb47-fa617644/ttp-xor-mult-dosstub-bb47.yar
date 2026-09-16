rule TTP_XOR_MULT_DOSStub_bb47 {
  strings:
    $key_bb47 = { ef 2f [2] 9b 37 [2] dc 35 [2] 9b 24 [2] d5 28 [2] d9 22 [2] ce 29 [2] d5 67 [2] e8 }

  condition:
    any of them
}