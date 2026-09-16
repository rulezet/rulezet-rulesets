rule TTP_XOR_MULT_DOSStub_998f {
  strings:
    $key_998f = { cd e7 [2] b9 ff [2] fe fd [2] b9 ec [2] f7 e0 [2] fb ea [2] ec e1 [2] f7 af [2] ca }

  condition:
    any of them
}