rule TTP_XOR_MULT_DOSStub_9d55 {
  strings:
    $key_9d55 = { c9 3d [2] bd 25 [2] fa 27 [2] bd 36 [2] f3 3a [2] ff 30 [2] e8 3b [2] f3 75 [2] ce }

  condition:
    any of them
}