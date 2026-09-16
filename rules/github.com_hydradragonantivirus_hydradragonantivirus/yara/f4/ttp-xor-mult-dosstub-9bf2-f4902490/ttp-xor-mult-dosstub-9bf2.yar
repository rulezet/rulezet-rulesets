rule TTP_XOR_MULT_DOSStub_9bf2 {
  strings:
    $key_9bf2 = { cf 9a [2] bb 82 [2] fc 80 [2] bb 91 [2] f5 9d [2] f9 97 [2] ee 9c [2] f5 d2 [2] c8 }

  condition:
    any of them
}