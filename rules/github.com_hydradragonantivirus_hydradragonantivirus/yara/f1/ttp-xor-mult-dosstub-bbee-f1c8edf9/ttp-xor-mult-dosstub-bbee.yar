rule TTP_XOR_MULT_DOSStub_bbee {
  strings:
    $key_bbee = { ef 86 [2] 9b 9e [2] dc 9c [2] 9b 8d [2] d5 81 [2] d9 8b [2] ce 80 [2] d5 ce [2] e8 }

  condition:
    any of them
}