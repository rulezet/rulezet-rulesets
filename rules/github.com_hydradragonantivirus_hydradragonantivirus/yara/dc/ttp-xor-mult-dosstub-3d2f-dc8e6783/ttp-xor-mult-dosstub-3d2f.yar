rule TTP_XOR_MULT_DOSStub_3d2f {
  strings:
    $key_3d2f = { 69 47 [2] 1d 5f [2] 5a 5d [2] 1d 4c [2] 53 40 [2] 5f 4a [2] 48 41 [2] 53 0f [2] 6e }

  condition:
    any of them
}