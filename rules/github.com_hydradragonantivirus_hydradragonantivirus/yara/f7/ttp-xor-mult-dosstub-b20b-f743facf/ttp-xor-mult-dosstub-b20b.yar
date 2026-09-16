rule TTP_XOR_MULT_DOSStub_b20b {
  strings:
    $key_b20b = { e6 63 [2] 92 7b [2] d5 79 [2] 92 68 [2] dc 64 [2] d0 6e [2] c7 65 [2] dc 2b [2] e1 }

  condition:
    any of them
}