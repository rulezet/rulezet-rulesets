rule TTP_XOR_MULT_DOSStub_bbeb {
  strings:
    $key_bbeb = { ef 83 [2] 9b 9b [2] dc 99 [2] 9b 88 [2] d5 84 [2] d9 8e [2] ce 85 [2] d5 cb [2] e8 }

  condition:
    any of them
}