rule TTP_XOR_MULT_DOSStub_99cc {
  strings:
    $key_99cc = { cd a4 [2] b9 bc [2] fe be [2] b9 af [2] f7 a3 [2] fb a9 [2] ec a2 [2] f7 ec [2] ca }

  condition:
    any of them
}