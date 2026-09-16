rule TTP_XOR_MULT_DOSStub_0bee {
  strings:
    $key_0bee = { 5f 86 [2] 2b 9e [2] 6c 9c [2] 2b 8d [2] 65 81 [2] 69 8b [2] 7e 80 [2] 65 ce [2] 58 }

  condition:
    any of them
}