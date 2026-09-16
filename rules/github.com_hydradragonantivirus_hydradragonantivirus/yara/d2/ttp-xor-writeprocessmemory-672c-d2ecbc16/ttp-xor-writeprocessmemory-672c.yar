rule TTP_XOR_WriteProcessMemory_672c {
  strings:
    $key_672c = { 30 5e [2] 02 7c [2] 04 49 [2] 2a 49 [2] 15 55 }

  condition:
    any of them
}