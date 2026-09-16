rule TTP_XOR_MULT_DOSStub_dcf4 {
  strings:
    $key_dcf4 = { 88 9c [2] fc 84 [2] bb 86 [2] fc 97 [2] b2 9b [2] be 91 [2] a9 9a [2] b2 d4 [2] 8f }

  condition:
    any of them
}