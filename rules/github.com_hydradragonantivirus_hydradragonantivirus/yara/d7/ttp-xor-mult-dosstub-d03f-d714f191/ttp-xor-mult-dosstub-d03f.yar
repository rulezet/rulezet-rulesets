rule TTP_XOR_MULT_DOSStub_d03f {
  strings:
    $key_d03f = { 84 57 [2] f0 4f [2] b7 4d [2] f0 5c [2] be 50 [2] b2 5a [2] a5 51 [2] be 1f [2] 83 }

  condition:
    any of them
}