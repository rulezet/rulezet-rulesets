rule TTP_XOR_MULT_DOSStub_47fc {
  strings:
    $key_47fc = { 13 94 [2] 67 8c [2] 20 8e [2] 67 9f [2] 29 93 [2] 25 99 [2] 32 92 [2] 29 dc [2] 14 }

  condition:
    any of them
}