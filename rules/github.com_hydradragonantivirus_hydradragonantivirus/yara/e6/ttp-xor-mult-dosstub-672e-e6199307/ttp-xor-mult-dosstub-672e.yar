rule TTP_XOR_MULT_DOSStub_672e {
  strings:
    $key_672e = { 33 46 [2] 47 5e [2] 00 5c [2] 47 4d [2] 09 41 [2] 05 4b [2] 12 40 [2] 09 0e [2] 34 }

  condition:
    any of them
}