rule TTP_XOR_MULT_DOSStub_9d9d {
  strings:
    $key_9d9d = { c9 f5 [2] bd ed [2] fa ef [2] bd fe [2] f3 f2 [2] ff f8 [2] e8 f3 [2] f3 bd [2] ce }

  condition:
    any of them
}