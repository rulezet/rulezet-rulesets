rule TTP_XOR_MULT_DOSStub_1b1f {
  strings:
    $key_1b1f = { 4f 77 [2] 3b 6f [2] 7c 6d [2] 3b 7c [2] 75 70 [2] 79 7a [2] 6e 71 [2] 75 3f [2] 48 }

  condition:
    any of them
}