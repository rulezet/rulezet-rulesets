rule TTP_XOR_MULT_DOSStub_b774 {
  strings:
    $key_b774 = { e3 1c [2] 97 04 [2] d0 06 [2] 97 17 [2] d9 1b [2] d5 11 [2] c2 1a [2] d9 54 [2] e4 }

  condition:
    any of them
}