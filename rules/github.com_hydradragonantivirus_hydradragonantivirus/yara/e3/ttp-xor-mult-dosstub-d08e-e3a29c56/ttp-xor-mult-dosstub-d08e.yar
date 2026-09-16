rule TTP_XOR_MULT_DOSStub_d08e {
  strings:
    $key_d08e = { 84 e6 [2] f0 fe [2] b7 fc [2] f0 ed [2] be e1 [2] b2 eb [2] a5 e0 [2] be ae [2] 83 }

  condition:
    any of them
}