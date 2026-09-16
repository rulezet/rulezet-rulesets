rule TTP_XOR_MULT_DOSStub_9bba {
  strings:
    $key_9bba = { cf d2 [2] bb ca [2] fc c8 [2] bb d9 [2] f5 d5 [2] f9 df [2] ee d4 [2] f5 9a [2] c8 }

  condition:
    any of them
}