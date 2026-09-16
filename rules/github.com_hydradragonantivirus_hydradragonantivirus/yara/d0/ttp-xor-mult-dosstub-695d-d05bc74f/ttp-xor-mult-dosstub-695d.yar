rule TTP_XOR_MULT_DOSStub_695d {
  strings:
    $key_695d = { 3d 35 [2] 49 2d [2] 0e 2f [2] 49 3e [2] 07 32 [2] 0b 38 [2] 1c 33 [2] 07 7d [2] 3a }

  condition:
    any of them
}