rule TTP_XOR_MULT_DOSStub_431f {
  strings:
    $key_431f = { 17 77 [2] 63 6f [2] 24 6d [2] 63 7c [2] 2d 70 [2] 21 7a [2] 36 71 [2] 2d 3f [2] 10 }

  condition:
    any of them
}