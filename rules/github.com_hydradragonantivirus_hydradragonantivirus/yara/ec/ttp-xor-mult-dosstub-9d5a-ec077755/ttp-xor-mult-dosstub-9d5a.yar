rule TTP_XOR_MULT_DOSStub_9d5a {
  strings:
    $key_9d5a = { c9 32 [2] bd 2a [2] fa 28 [2] bd 39 [2] f3 35 [2] ff 3f [2] e8 34 [2] f3 7a [2] ce }

  condition:
    any of them
}