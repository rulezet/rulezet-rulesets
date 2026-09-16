rule TTP_XOR_MULT_DOSStub_6e2f {
  strings:
    $key_6e2f = { 3a 47 [2] 4e 5f [2] 09 5d [2] 4e 4c [2] 00 40 [2] 0c 4a [2] 1b 41 [2] 00 0f [2] 3d }

  condition:
    any of them
}