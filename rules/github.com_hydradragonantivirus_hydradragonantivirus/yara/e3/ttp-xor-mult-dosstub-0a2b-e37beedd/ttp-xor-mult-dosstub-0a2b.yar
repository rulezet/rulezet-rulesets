rule TTP_XOR_MULT_DOSStub_0a2b {
  strings:
    $key_0a2b = { 5e 43 [2] 2a 5b [2] 6d 59 [2] 2a 48 [2] 64 44 [2] 68 4e [2] 7f 45 [2] 64 0b [2] 59 }

  condition:
    any of them
}