rule TTP_XOR_MULT_DOSStub_2eee {
  strings:
    $key_2eee = { 7a 86 [2] 0e 9e [2] 49 9c [2] 0e 8d [2] 40 81 [2] 4c 8b [2] 5b 80 [2] 40 ce [2] 7d }

  condition:
    any of them
}