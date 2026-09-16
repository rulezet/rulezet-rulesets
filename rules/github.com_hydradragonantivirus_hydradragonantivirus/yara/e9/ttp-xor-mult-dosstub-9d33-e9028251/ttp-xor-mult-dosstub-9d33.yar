rule TTP_XOR_MULT_DOSStub_9d33 {
  strings:
    $key_9d33 = { c9 5b [2] bd 43 [2] fa 41 [2] bd 50 [2] f3 5c [2] ff 56 [2] e8 5d [2] f3 13 [2] ce }

  condition:
    any of them
}