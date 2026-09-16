rule TTP_XOR_MULT_DOSStub_0d2f {
  strings:
    $key_0d2f = { 59 47 [2] 2d 5f [2] 6a 5d [2] 2d 4c [2] 63 40 [2] 6f 4a [2] 78 41 [2] 63 0f [2] 5e }

  condition:
    any of them
}