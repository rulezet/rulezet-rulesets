rule TTP_XOR_MULT_DOSStub_9d39 {
  strings:
    $key_9d39 = { c9 51 [2] bd 49 [2] fa 4b [2] bd 5a [2] f3 56 [2] ff 5c [2] e8 57 [2] f3 19 [2] ce }

  condition:
    any of them
}