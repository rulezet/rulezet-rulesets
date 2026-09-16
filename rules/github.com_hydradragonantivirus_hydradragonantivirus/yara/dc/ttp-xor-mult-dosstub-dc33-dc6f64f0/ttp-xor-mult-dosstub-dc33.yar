rule TTP_XOR_MULT_DOSStub_dc33 {
  strings:
    $key_dc33 = { 88 5b [2] fc 43 [2] bb 41 [2] fc 50 [2] b2 5c [2] be 56 [2] a9 5d [2] b2 13 [2] 8f }

  condition:
    any of them
}