rule TTP_XOR_MULT_DOSStub_0afc {
  strings:
    $key_0afc = { 5e 94 [2] 2a 8c [2] 6d 8e [2] 2a 9f [2] 64 93 [2] 68 99 [2] 7f 92 [2] 64 dc [2] 59 }

  condition:
    any of them
}