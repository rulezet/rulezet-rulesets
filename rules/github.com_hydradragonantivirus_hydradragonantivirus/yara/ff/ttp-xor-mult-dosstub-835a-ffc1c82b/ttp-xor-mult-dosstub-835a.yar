rule TTP_XOR_MULT_DOSStub_835a {
  strings:
    $key_835a = { d7 32 [2] a3 2a [2] e4 28 [2] a3 39 [2] ed 35 [2] e1 3f [2] f6 34 [2] ed 7a [2] d0 }

  condition:
    any of them
}