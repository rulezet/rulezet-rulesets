rule TTP_XOR_MULT_DOSStub_6fee {
  strings:
    $key_6fee = { 3b 86 [2] 4f 9e [2] 08 9c [2] 4f 8d [2] 01 81 [2] 0d 8b [2] 1a 80 [2] 01 ce [2] 3c }

  condition:
    any of them
}