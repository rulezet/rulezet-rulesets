rule TTP_XOR_MULT_DOSStub_9d69 {
  strings:
    $key_9d69 = { c9 01 [2] bd 19 [2] fa 1b [2] bd 0a [2] f3 06 [2] ff 0c [2] e8 07 [2] f3 49 [2] ce }

  condition:
    any of them
}