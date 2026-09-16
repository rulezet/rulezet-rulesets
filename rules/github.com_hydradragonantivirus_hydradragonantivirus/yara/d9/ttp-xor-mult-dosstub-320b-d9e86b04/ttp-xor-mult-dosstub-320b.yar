rule TTP_XOR_MULT_DOSStub_320b {
  strings:
    $key_320b = { 66 63 [2] 12 7b [2] 55 79 [2] 12 68 [2] 5c 64 [2] 50 6e [2] 47 65 [2] 5c 2b [2] 61 }

  condition:
    any of them
}