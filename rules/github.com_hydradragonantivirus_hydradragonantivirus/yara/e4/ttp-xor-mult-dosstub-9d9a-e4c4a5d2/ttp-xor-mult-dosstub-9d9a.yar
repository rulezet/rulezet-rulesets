rule TTP_XOR_MULT_DOSStub_9d9a {
  strings:
    $key_9d9a = { c9 f2 [2] bd ea [2] fa e8 [2] bd f9 [2] f3 f5 [2] ff ff [2] e8 f4 [2] f3 ba [2] ce }

  condition:
    any of them
}