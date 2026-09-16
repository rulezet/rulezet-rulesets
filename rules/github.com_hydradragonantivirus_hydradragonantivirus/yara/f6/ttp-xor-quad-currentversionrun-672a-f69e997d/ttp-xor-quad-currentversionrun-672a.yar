rule TTP_XOR_QUAD_CurrentVersionRun_672a {
  strings:
    $key_672a = { 34 45 [2] 10 4b [2] 3b 67 [2] 15 45 [2] 01 5e [2] 0e 44 [2] 10 59 [2] 12 58 [2] 09 5e [2] 15 59 [2] 09 76 }

  condition:
    any of them
}