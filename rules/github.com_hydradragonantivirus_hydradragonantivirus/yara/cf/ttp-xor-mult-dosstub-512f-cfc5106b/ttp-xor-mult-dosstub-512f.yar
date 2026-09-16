rule TTP_XOR_MULT_DOSStub_512f {
  strings:
    $key_512f = { 05 47 [2] 71 5f [2] 36 5d [2] 71 4c [2] 3f 40 [2] 33 4a [2] 24 41 [2] 3f 0f [2] 02 }

  condition:
    any of them
}