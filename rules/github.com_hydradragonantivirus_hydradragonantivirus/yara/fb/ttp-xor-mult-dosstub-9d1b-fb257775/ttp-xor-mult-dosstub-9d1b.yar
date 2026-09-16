rule TTP_XOR_MULT_DOSStub_9d1b {
  strings:
    $key_9d1b = { c9 73 [2] bd 6b [2] fa 69 [2] bd 78 [2] f3 74 [2] ff 7e [2] e8 75 [2] f3 3b [2] ce }

  condition:
    any of them
}