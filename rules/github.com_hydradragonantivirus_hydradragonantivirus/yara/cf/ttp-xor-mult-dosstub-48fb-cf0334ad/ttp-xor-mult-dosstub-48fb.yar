rule TTP_XOR_MULT_DOSStub_48fb {
  strings:
    $key_48fb = { 1c 93 [2] 68 8b [2] 2f 89 [2] 68 98 [2] 26 94 [2] 2a 9e [2] 3d 95 [2] 26 db [2] 1b }

  condition:
    any of them
}