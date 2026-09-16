rule TTP_XOR_MULT_DOSStub_517d {
  strings:
    $key_517d = { 05 15 [2] 71 0d [2] 36 0f [2] 71 1e [2] 3f 12 [2] 33 18 [2] 24 13 [2] 3f 5d [2] 02 }

  condition:
    any of them
}