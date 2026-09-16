rule TTP_XOR_MULT_DOSStub_9d14 {
  strings:
    $key_9d14 = { c9 7c [2] bd 64 [2] fa 66 [2] bd 77 [2] f3 7b [2] ff 71 [2] e8 7a [2] f3 34 [2] ce }

  condition:
    any of them
}