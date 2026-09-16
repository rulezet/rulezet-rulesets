rule TTP_XOR_MULT_DOSStub_dcf9 {
  strings:
    $key_dcf9 = { 88 91 [2] fc 89 [2] bb 8b [2] fc 9a [2] b2 96 [2] be 9c [2] a9 97 [2] b2 d9 [2] 8f }

  condition:
    any of them
}