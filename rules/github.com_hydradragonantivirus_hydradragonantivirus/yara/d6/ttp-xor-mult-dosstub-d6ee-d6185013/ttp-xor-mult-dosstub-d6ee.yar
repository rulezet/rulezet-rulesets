rule TTP_XOR_MULT_DOSStub_d6ee {
  strings:
    $key_d6ee = { 82 86 [2] f6 9e [2] b1 9c [2] f6 8d [2] b8 81 [2] b4 8b [2] a3 80 [2] b8 ce [2] 85 }

  condition:
    any of them
}