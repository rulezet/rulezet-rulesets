rule TTP_XOR_MULT_DOSStub_9de9 {
  strings:
    $key_9de9 = { c9 81 [2] bd 99 [2] fa 9b [2] bd 8a [2] f3 86 [2] ff 8c [2] e8 87 [2] f3 c9 [2] ce }

  condition:
    any of them
}