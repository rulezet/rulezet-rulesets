rule TTP_XOR_MULT_DOSStub_2952 {
  strings:
    $key_2952 = { 7d 3a [2] 09 22 [2] 4e 20 [2] 09 31 [2] 47 3d [2] 4b 37 [2] 5c 3c [2] 47 72 [2] 7a }

  condition:
    any of them
}