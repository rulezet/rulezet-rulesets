rule TTP_XOR_MULT_DOSStub_809c {
  strings:
    $key_809c = { d4 f4 [2] a0 ec [2] e7 ee [2] a0 ff [2] ee f3 [2] e2 f9 [2] f5 f2 [2] ee bc [2] d3 }

  condition:
    any of them
}