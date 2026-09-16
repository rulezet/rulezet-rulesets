rule TTP_XOR_MULT_DOSStub_480b {
  strings:
    $key_480b = { 1c 63 [2] 68 7b [2] 2f 79 [2] 68 68 [2] 26 64 [2] 2a 6e [2] 3d 65 [2] 26 2b [2] 1b }

  condition:
    any of them
}