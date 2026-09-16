rule TTP_XOR_MULT_DOSStub_007f {
  strings:
    $key_007f = { 54 17 [2] 20 0f [2] 67 0d [2] 20 1c [2] 6e 10 [2] 62 1a [2] 75 11 [2] 6e 5f [2] 53 }

  condition:
    any of them
}