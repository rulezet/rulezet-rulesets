rule TTP_XOR_MULT_DOSStub_998e {
  strings:
    $key_998e = { cd e6 [2] b9 fe [2] fe fc [2] b9 ed [2] f7 e1 [2] fb eb [2] ec e0 [2] f7 ae [2] ca }

  condition:
    any of them
}