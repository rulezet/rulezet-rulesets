rule TTP_XOR_MULT_DOSStub_d083 {
  strings:
    $key_d083 = { 84 eb [2] f0 f3 [2] b7 f1 [2] f0 e0 [2] be ec [2] b2 e6 [2] a5 ed [2] be a3 [2] 83 }

  condition:
    any of them
}