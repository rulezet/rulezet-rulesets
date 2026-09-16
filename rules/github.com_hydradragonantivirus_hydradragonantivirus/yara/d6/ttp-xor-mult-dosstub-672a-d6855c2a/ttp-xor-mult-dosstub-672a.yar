rule TTP_XOR_MULT_DOSStub_672a {
  strings:
    $key_672a = { 33 42 [2] 47 5a [2] 00 58 [2] 47 49 [2] 09 45 [2] 05 4f [2] 12 44 [2] 09 0a [2] 34 }

  condition:
    any of them
}