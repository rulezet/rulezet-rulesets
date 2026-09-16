rule TTP_XOR_MULT_DOSStub_faeb {
  strings:
    $key_faeb = { ae 83 [2] da 9b [2] 9d 99 [2] da 88 [2] 94 84 [2] 98 8e [2] 8f 85 [2] 94 cb [2] a9 }

  condition:
    any of them
}