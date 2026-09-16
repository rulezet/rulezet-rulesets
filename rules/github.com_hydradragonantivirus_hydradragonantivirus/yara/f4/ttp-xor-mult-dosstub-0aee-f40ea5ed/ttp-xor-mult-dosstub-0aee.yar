rule TTP_XOR_MULT_DOSStub_0aee {
  strings:
    $key_0aee = { 5e 86 [2] 2a 9e [2] 6d 9c [2] 2a 8d [2] 64 81 [2] 68 8b [2] 7f 80 [2] 64 ce [2] 59 }

  condition:
    any of them
}