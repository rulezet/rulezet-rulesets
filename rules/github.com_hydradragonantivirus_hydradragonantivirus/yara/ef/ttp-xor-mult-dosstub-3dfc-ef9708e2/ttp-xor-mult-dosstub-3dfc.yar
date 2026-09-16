rule TTP_XOR_MULT_DOSStub_3dfc {
  strings:
    $key_3dfc = { 69 94 [2] 1d 8c [2] 5a 8e [2] 1d 9f [2] 53 93 [2] 5f 99 [2] 48 92 [2] 53 dc [2] 6e }

  condition:
    any of them
}