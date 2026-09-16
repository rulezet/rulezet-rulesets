rule TTP_XOR_MULT_DOSStub_d00a {
  strings:
    $key_d00a = { 84 62 [2] f0 7a [2] b7 78 [2] f0 69 [2] be 65 [2] b2 6f [2] a5 64 [2] be 2a [2] 83 }

  condition:
    any of them
}