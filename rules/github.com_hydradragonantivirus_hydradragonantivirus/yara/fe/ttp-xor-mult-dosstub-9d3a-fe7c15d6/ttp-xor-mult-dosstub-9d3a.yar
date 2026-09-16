rule TTP_XOR_MULT_DOSStub_9d3a {
  strings:
    $key_9d3a = { c9 52 [2] bd 4a [2] fa 48 [2] bd 59 [2] f3 55 [2] ff 5f [2] e8 54 [2] f3 1a [2] ce }

  condition:
    any of them
}