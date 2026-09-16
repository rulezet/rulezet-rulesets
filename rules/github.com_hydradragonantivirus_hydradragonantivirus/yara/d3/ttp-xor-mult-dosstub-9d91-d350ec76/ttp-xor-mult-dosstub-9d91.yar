rule TTP_XOR_MULT_DOSStub_9d91 {
  strings:
    $key_9d91 = { c9 f9 [2] bd e1 [2] fa e3 [2] bd f2 [2] f3 fe [2] ff f4 [2] e8 ff [2] f3 b1 [2] ce }

  condition:
    any of them
}