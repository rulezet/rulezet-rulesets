rule TTP_XOR_MULT_DOSStub_9191 {
  strings:
    $key_9191 = { c5 f9 [2] b1 e1 [2] f6 e3 [2] b1 f2 [2] ff fe [2] f3 f4 [2] e4 ff [2] ff b1 [2] c2 }

  condition:
    any of them
}