rule TTP_XOR_MULT_DOSStub_9fa4 {
  strings:
    $key_9fa4 = { cb cc [2] bf d4 [2] f8 d6 [2] bf c7 [2] f1 cb [2] fd c1 [2] ea ca [2] f1 84 [2] cc }

  condition:
    any of them
}