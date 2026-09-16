rule TTP_XOR_MULT_DOSStub_d0f9 {
  strings:
    $key_d0f9 = { 84 91 [2] f0 89 [2] b7 8b [2] f0 9a [2] be 96 [2] b2 9c [2] a5 97 [2] be d9 [2] 83 }

  condition:
    any of them
}