rule TTP_XOR_MULT_DOSStub_1d2f {
  strings:
    $key_1d2f = { 49 47 [2] 3d 5f [2] 7a 5d [2] 3d 4c [2] 73 40 [2] 7f 4a [2] 68 41 [2] 73 0f [2] 4e }

  condition:
    any of them
}