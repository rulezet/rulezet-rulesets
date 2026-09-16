rule TTP_XOR_MULT_DOSStub_4c1f {
  strings:
    $key_4c1f = { 18 77 [2] 6c 6f [2] 2b 6d [2] 6c 7c [2] 22 70 [2] 2e 7a [2] 39 71 [2] 22 3f [2] 1f }

  condition:
    any of them
}