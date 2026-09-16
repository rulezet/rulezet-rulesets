rule TTP_XOR_MULT_DOSStub_bb5b {
  strings:
    $key_bb5b = { ef 33 [2] 9b 2b [2] dc 29 [2] 9b 38 [2] d5 34 [2] d9 3e [2] ce 35 [2] d5 7b [2] e8 }

  condition:
    any of them
}