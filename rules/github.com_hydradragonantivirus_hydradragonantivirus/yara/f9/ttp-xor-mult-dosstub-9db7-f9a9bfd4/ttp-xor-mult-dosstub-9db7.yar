rule TTP_XOR_MULT_DOSStub_9db7 {
  strings:
    $key_9db7 = { c9 df [2] bd c7 [2] fa c5 [2] bd d4 [2] f3 d8 [2] ff d2 [2] e8 d9 [2] f3 97 [2] ce }

  condition:
    any of them
}