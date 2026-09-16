rule TTP_XOR_MULT_DOSStub_d90d {
  strings:
    $key_d90d = { 8d 65 [2] f9 7d [2] be 7f [2] f9 6e [2] b7 62 [2] bb 68 [2] ac 63 [2] b7 2d [2] 8a }

  condition:
    any of them
}