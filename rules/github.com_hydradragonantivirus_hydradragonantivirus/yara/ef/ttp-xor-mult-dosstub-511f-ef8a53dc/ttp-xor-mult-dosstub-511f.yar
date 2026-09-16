rule TTP_XOR_MULT_DOSStub_511f {
  strings:
    $key_511f = { 05 77 [2] 71 6f [2] 36 6d [2] 71 7c [2] 3f 70 [2] 33 7a [2] 24 71 [2] 3f 3f [2] 02 }

  condition:
    any of them
}