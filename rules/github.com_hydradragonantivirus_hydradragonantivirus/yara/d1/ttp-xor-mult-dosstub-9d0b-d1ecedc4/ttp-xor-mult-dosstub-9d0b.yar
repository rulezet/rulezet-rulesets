rule TTP_XOR_MULT_DOSStub_9d0b {
  strings:
    $key_9d0b = { c9 63 [2] bd 7b [2] fa 79 [2] bd 68 [2] f3 64 [2] ff 6e [2] e8 65 [2] f3 2b [2] ce }

  condition:
    any of them
}