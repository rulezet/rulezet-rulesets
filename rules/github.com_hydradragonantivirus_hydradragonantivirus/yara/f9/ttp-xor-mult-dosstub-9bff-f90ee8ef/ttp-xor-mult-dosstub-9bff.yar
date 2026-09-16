rule TTP_XOR_MULT_DOSStub_9bff {
  strings:
    $key_9bff = { cf 97 [2] bb 8f [2] fc 8d [2] bb 9c [2] f5 90 [2] f9 9a [2] ee 91 [2] f5 df [2] c8 }

  condition:
    any of them
}