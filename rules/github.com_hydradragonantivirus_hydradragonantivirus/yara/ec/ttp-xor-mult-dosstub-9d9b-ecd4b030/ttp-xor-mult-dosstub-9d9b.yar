rule TTP_XOR_MULT_DOSStub_9d9b {
  strings:
    $key_9d9b = { c9 f3 [2] bd eb [2] fa e9 [2] bd f8 [2] f3 f4 [2] ff fe [2] e8 f5 [2] f3 bb [2] ce }

  condition:
    any of them
}