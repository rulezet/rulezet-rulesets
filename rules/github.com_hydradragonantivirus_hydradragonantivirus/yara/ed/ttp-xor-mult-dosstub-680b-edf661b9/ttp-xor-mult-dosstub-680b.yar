rule TTP_XOR_MULT_DOSStub_680b {
  strings:
    $key_680b = { 3c 63 [2] 48 7b [2] 0f 79 [2] 48 68 [2] 06 64 [2] 0a 6e [2] 1d 65 [2] 06 2b [2] 3b }

  condition:
    any of them
}