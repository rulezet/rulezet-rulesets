rule TTP_XOR_WriteProcessMemory_3afc {
  strings:
    $key_3afc = { 6d 8e [2] 5f ac [2] 59 99 [2] 77 99 [2] 48 85 }

  condition:
    any of them
}