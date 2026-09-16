rule TTP_XOR_MULT_DOSStub_06ee {
  strings:
    $key_06ee = { 52 86 [2] 26 9e [2] 61 9c [2] 26 8d [2] 68 81 [2] 64 8b [2] 73 80 [2] 68 ce [2] 55 }

  condition:
    any of them
}