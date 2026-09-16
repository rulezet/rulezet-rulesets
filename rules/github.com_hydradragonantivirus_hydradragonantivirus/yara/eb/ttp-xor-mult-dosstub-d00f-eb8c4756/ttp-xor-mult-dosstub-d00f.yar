rule TTP_XOR_MULT_DOSStub_d00f {
  strings:
    $key_d00f = { 84 67 [2] f0 7f [2] b7 7d [2] f0 6c [2] be 60 [2] b2 6a [2] a5 61 [2] be 2f [2] 83 }

  condition:
    any of them
}