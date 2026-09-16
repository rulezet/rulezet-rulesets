rule TTP_XOR_MULT_DOSStub_4831 {
  strings:
    $key_4831 = { 1c 59 [2] 68 41 [2] 2f 43 [2] 68 52 [2] 26 5e [2] 2a 54 [2] 3d 5f [2] 26 11 [2] 1b }

  condition:
    any of them
}