rule TTP_XOR_MULT_DOSStub_28ee {
  strings:
    $key_28ee = { 7c 86 [2] 08 9e [2] 4f 9c [2] 08 8d [2] 46 81 [2] 4a 8b [2] 5d 80 [2] 46 ce [2] 7b }

  condition:
    any of them
}