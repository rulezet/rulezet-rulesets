rule TTP_XOR_MULT_DOSStub_5dee {
  strings:
    $key_5dee = { 09 86 [2] 7d 9e [2] 3a 9c [2] 7d 8d [2] 33 81 [2] 3f 8b [2] 28 80 [2] 33 ce [2] 0e }

  condition:
    any of them
}