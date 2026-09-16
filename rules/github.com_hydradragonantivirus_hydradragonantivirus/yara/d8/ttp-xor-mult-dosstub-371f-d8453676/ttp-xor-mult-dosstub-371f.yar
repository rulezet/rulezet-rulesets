rule TTP_XOR_MULT_DOSStub_371f {
  strings:
    $key_371f = { 63 77 [2] 17 6f [2] 50 6d [2] 17 7c [2] 59 70 [2] 55 7a [2] 42 71 [2] 59 3f [2] 64 }

  condition:
    any of them
}