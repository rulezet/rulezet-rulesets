rule TTP_XOR_MULT_DOSStub_9d7b {
  strings:
    $key_9d7b = { c9 13 [2] bd 0b [2] fa 09 [2] bd 18 [2] f3 14 [2] ff 1e [2] e8 15 [2] f3 5b [2] ce }

  condition:
    any of them
}