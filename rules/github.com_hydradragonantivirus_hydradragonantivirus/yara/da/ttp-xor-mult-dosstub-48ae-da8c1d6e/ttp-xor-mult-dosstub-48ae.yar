rule TTP_XOR_MULT_DOSStub_48ae {
  strings:
    $key_48ae = { 1c c6 [2] 68 de [2] 2f dc [2] 68 cd [2] 26 c1 [2] 2a cb [2] 3d c0 [2] 26 8e [2] 1b }

  condition:
    any of them
}