rule TTP_XOR_MULT_DOSStub_9d02 {
  strings:
    $key_9d02 = { c9 6a [2] bd 72 [2] fa 70 [2] bd 61 [2] f3 6d [2] ff 67 [2] e8 6c [2] f3 22 [2] ce }

  condition:
    any of them
}