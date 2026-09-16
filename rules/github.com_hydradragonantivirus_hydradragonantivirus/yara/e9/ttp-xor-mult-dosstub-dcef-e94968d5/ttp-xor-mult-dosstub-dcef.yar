rule TTP_XOR_MULT_DOSStub_dcef {
  strings:
    $key_dcef = { 88 87 [2] fc 9f [2] bb 9d [2] fc 8c [2] b2 80 [2] be 8a [2] a9 81 [2] b2 cf [2] 8f }

  condition:
    any of them
}