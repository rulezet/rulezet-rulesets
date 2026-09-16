rule TTP_XOR_MULT_DOSStub_3bee {
  strings:
    $key_3bee = { 6f 86 [2] 1b 9e [2] 5c 9c [2] 1b 8d [2] 55 81 [2] 59 8b [2] 4e 80 [2] 55 ce [2] 68 }

  condition:
    any of them
}