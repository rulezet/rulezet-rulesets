rule TTP_XOR_MULT_DOSStub_d022 {
  strings:
    $key_d022 = { 84 4a [2] f0 52 [2] b7 50 [2] f0 41 [2] be 4d [2] b2 47 [2] a5 4c [2] be 02 [2] 83 }

  condition:
    any of them
}