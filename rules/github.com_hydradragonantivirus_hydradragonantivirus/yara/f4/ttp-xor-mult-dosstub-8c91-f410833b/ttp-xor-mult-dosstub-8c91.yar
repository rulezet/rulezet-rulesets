rule TTP_XOR_MULT_DOSStub_8c91 {
  strings:
    $key_8c91 = { d8 f9 [2] ac e1 [2] eb e3 [2] ac f2 [2] e2 fe [2] ee f4 [2] f9 ff [2] e2 b1 [2] df }

  condition:
    any of them
}