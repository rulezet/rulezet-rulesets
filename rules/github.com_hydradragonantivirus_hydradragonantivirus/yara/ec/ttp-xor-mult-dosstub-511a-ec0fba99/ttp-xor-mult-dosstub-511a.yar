rule TTP_XOR_MULT_DOSStub_511a {
  strings:
    $key_511a = { 05 72 [2] 71 6a [2] 36 68 [2] 71 79 [2] 3f 75 [2] 33 7f [2] 24 74 [2] 3f 3a [2] 02 }

  condition:
    any of them
}