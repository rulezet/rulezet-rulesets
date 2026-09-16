rule TTP_XOR_MULT_DOSStub_9db1 {
  strings:
    $key_9db1 = { c9 d9 [2] bd c1 [2] fa c3 [2] bd d2 [2] f3 de [2] ff d4 [2] e8 df [2] f3 91 [2] ce }

  condition:
    any of them
}