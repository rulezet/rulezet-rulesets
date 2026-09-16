rule TTP_XOR_MULT_DOSStub_330b {
  strings:
    $key_330b = { 67 63 [2] 13 7b [2] 54 79 [2] 13 68 [2] 5d 64 [2] 51 6e [2] 46 65 [2] 5d 2b [2] 60 }

  condition:
    any of them
}