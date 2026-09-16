rule TTP_XOR_MULT_DOSStub_868e {
  strings:
    $key_868e = { d2 e6 [2] a6 fe [2] e1 fc [2] a6 ed [2] e8 e1 [2] e4 eb [2] f3 e0 [2] e8 ae [2] d5 }

  condition:
    any of them
}