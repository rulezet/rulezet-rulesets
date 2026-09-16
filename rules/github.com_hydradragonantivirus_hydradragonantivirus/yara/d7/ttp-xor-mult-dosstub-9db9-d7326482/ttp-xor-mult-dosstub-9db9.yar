rule TTP_XOR_MULT_DOSStub_9db9 {
  strings:
    $key_9db9 = { c9 d1 [2] bd c9 [2] fa cb [2] bd da [2] f3 d6 [2] ff dc [2] e8 d7 [2] f3 99 [2] ce }

  condition:
    any of them
}