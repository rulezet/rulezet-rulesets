rule TTP_XOR_MULT_DOSStub_bb06 {
  strings:
    $key_bb06 = { ef 6e [2] 9b 76 [2] dc 74 [2] 9b 65 [2] d5 69 [2] d9 63 [2] ce 68 [2] d5 26 [2] e8 }

  condition:
    any of them
}