rule TTP_XOR_MULT_DOSStub_0fee {
  strings:
    $key_0fee = { 5b 86 [2] 2f 9e [2] 68 9c [2] 2f 8d [2] 61 81 [2] 6d 8b [2] 7a 80 [2] 61 ce [2] 5c }

  condition:
    any of them
}