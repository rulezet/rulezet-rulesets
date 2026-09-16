rule TTP_XOR_MULT_DOSStub_908e {
  strings:
    $key_908e = { c4 e6 [2] b0 fe [2] f7 fc [2] b0 ed [2] fe e1 [2] f2 eb [2] e5 e0 [2] fe ae [2] c3 }

  condition:
    any of them
}