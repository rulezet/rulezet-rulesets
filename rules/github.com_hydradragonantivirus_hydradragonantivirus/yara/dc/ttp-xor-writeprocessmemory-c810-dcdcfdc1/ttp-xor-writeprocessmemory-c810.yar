rule TTP_XOR_WriteProcessMemory_c810 {
  strings:
    $key_c810 = { 9f 62 [2] ad 40 [2] ab 75 [2] 85 75 [2] ba 69 }

  condition:
    any of them
}