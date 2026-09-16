rule TTP_XOR_MULT_DOSStub_9d52 {
  strings:
    $key_9d52 = { c9 3a [2] bd 22 [2] fa 20 [2] bd 31 [2] f3 3d [2] ff 37 [2] e8 3c [2] f3 72 [2] ce }

  condition:
    any of them
}