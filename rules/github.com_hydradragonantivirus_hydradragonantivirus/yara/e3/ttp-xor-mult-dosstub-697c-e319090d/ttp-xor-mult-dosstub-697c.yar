rule TTP_XOR_MULT_DOSStub_697c {
  strings:
    $key_697c = { 3d 14 [2] 49 0c [2] 0e 0e [2] 49 1f [2] 07 13 [2] 0b 19 [2] 1c 12 [2] 07 5c [2] 3a }

  condition:
    any of them
}