rule TTP_XOR_MULT_DOSStub_9fa3 {
  strings:
    $key_9fa3 = { cb cb [2] bf d3 [2] f8 d1 [2] bf c0 [2] f1 cc [2] fd c6 [2] ea cd [2] f1 83 [2] cc }

  condition:
    any of them
}