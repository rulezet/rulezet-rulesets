rule TTP_XOR_MULT_DOSStub_dcee {
  strings:
    $key_dcee = { 88 86 [2] fc 9e [2] bb 9c [2] fc 8d [2] b2 81 [2] be 8b [2] a9 80 [2] b2 ce [2] 8f }

  condition:
    any of them
}