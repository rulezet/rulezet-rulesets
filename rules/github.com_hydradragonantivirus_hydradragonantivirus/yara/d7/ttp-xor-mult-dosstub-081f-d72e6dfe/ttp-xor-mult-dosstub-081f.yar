rule TTP_XOR_MULT_DOSStub_081f {
  strings:
    $key_081f = { 5c 77 [2] 28 6f [2] 6f 6d [2] 28 7c [2] 66 70 [2] 6a 7a [2] 7d 71 [2] 66 3f [2] 5b }

  condition:
    any of them
}