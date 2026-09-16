rule TTP_XOR_MULT_DOSStub_e46f {
  strings:
    $key_e46f = { b0 07 [2] c4 1f [2] 83 1d [2] c4 0c [2] 8a 00 [2] 86 0a [2] 91 01 [2] 8a 4f [2] b7 }

  condition:
    any of them
}