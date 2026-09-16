rule TTP_XOR_MULT_DOSStub_294f {
  strings:
    $key_294f = { 7d 27 [2] 09 3f [2] 4e 3d [2] 09 2c [2] 47 20 [2] 4b 2a [2] 5c 21 [2] 47 6f [2] 7a }

  condition:
    any of them
}