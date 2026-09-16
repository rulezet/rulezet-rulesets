rule TTP_XOR_MULT_DOSStub_761f {
  strings:
    $key_761f = { 22 77 [2] 56 6f [2] 11 6d [2] 56 7c [2] 18 70 [2] 14 7a [2] 03 71 [2] 18 3f [2] 25 }

  condition:
    any of them
}