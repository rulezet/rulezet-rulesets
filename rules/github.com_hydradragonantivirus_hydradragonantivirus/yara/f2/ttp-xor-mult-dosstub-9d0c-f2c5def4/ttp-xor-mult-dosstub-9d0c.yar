rule TTP_XOR_MULT_DOSStub_9d0c {
  strings:
    $key_9d0c = { c9 64 [2] bd 7c [2] fa 7e [2] bd 6f [2] f3 63 [2] ff 69 [2] e8 62 [2] f3 2c [2] ce }

  condition:
    any of them
}