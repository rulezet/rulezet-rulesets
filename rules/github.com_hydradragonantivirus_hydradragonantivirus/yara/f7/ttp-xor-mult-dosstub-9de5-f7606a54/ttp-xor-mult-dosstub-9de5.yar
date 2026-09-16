rule TTP_XOR_MULT_DOSStub_9de5 {
  strings:
    $key_9de5 = { c9 8d [2] bd 95 [2] fa 97 [2] bd 86 [2] f3 8a [2] ff 80 [2] e8 8b [2] f3 c5 [2] ce }

  condition:
    any of them
}