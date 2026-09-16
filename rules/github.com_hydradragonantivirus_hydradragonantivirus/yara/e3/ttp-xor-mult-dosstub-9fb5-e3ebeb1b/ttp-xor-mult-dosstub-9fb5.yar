rule TTP_XOR_MULT_DOSStub_9fb5 {
  strings:
    $key_9fb5 = { cb dd [2] bf c5 [2] f8 c7 [2] bf d6 [2] f1 da [2] fd d0 [2] ea db [2] f1 95 [2] cc }

  condition:
    any of them
}