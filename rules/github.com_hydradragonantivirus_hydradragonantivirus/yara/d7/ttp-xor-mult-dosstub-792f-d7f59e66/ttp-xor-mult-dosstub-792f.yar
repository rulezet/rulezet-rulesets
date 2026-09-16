rule TTP_XOR_MULT_DOSStub_792f {
  strings:
    $key_792f = { 2d 47 [2] 59 5f [2] 1e 5d [2] 59 4c [2] 17 40 [2] 1b 4a [2] 0c 41 [2] 17 0f [2] 2a }

  condition:
    any of them
}