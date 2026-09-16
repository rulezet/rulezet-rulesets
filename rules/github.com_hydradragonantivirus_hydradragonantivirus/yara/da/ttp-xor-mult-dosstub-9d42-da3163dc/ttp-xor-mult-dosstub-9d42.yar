rule TTP_XOR_MULT_DOSStub_9d42 {
  strings:
    $key_9d42 = { c9 2a [2] bd 32 [2] fa 30 [2] bd 21 [2] f3 2d [2] ff 27 [2] e8 2c [2] f3 62 [2] ce }

  condition:
    any of them
}