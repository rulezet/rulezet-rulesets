rule TTP_XOR_MULT_DOSStub_930a {
  strings:
    $key_930a = { c7 62 [2] b3 7a [2] f4 78 [2] b3 69 [2] fd 65 [2] f1 6f [2] e6 64 [2] fd 2a [2] c0 }

  condition:
    any of them
}