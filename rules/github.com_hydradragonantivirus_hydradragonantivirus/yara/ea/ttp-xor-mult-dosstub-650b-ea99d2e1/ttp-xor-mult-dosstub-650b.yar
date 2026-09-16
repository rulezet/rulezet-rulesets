rule TTP_XOR_MULT_DOSStub_650b {
  strings:
    $key_650b = { 31 63 [2] 45 7b [2] 02 79 [2] 45 68 [2] 0b 64 [2] 07 6e [2] 10 65 [2] 0b 2b [2] 36 }

  condition:
    any of them
}