rule TTP_XOR_MULT_DOSStub_dc28 {
  strings:
    $key_dc28 = { 88 40 [2] fc 58 [2] bb 5a [2] fc 4b [2] b2 47 [2] be 4d [2] a9 46 [2] b2 08 [2] 8f }

  condition:
    any of them
}