rule TTP_XOR_MULT_DOSStub_1d3f {
  strings:
    $key_1d3f = { 49 57 [2] 3d 4f [2] 7a 4d [2] 3d 5c [2] 73 50 [2] 7f 5a [2] 68 51 [2] 73 1f [2] 4e }

  condition:
    any of them
}