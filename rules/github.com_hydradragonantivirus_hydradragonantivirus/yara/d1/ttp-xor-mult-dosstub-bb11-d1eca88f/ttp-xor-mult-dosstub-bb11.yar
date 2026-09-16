rule TTP_XOR_MULT_DOSStub_bb11 {
  strings:
    $key_bb11 = { ef 79 [2] 9b 61 [2] dc 63 [2] 9b 72 [2] d5 7e [2] d9 74 [2] ce 7f [2] d5 31 [2] e8 }

  condition:
    any of them
}