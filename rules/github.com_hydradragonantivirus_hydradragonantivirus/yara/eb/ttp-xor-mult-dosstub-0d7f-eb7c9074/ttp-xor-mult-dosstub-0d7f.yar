rule TTP_XOR_MULT_DOSStub_0d7f {
  strings:
    $key_0d7f = { 59 17 [2] 2d 0f [2] 6a 0d [2] 2d 1c [2] 63 10 [2] 6f 1a [2] 78 11 [2] 63 5f [2] 5e }

  condition:
    any of them
}