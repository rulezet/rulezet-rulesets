rule TTP_XOR_MULT_DOSStub_9d78 {
  strings:
    $key_9d78 = { c9 10 [2] bd 08 [2] fa 0a [2] bd 1b [2] f3 17 [2] ff 1d [2] e8 16 [2] f3 58 [2] ce }

  condition:
    any of them
}