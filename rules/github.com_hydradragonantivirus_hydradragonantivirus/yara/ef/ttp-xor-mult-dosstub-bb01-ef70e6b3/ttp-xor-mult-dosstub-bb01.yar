rule TTP_XOR_MULT_DOSStub_bb01 {
  strings:
    $key_bb01 = { ef 69 [2] 9b 71 [2] dc 73 [2] 9b 62 [2] d5 6e [2] d9 64 [2] ce 6f [2] d5 21 [2] e8 }

  condition:
    any of them
}