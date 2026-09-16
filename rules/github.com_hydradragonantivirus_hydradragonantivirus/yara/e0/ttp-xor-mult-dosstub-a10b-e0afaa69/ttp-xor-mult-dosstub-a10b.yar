rule TTP_XOR_MULT_DOSStub_a10b {
  strings:
    $key_a10b = { f5 63 [2] 81 7b [2] c6 79 [2] 81 68 [2] cf 64 [2] c3 6e [2] d4 65 [2] cf 2b [2] f2 }

  condition:
    any of them
}