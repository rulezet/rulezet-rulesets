rule TTP_XOR_MULT_DOSStub_fa4b {
  strings:
    $key_fa4b = { ae 23 [2] da 3b [2] 9d 39 [2] da 28 [2] 94 24 [2] 98 2e [2] 8f 25 [2] 94 6b [2] a9 }

  condition:
    any of them
}