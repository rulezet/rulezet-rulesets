rule TTP_XOR_MULT_DOSStub_541f {
  strings:
    $key_541f = { 00 77 [2] 74 6f [2] 33 6d [2] 74 7c [2] 3a 70 [2] 36 7a [2] 21 71 [2] 3a 3f [2] 07 }

  condition:
    any of them
}