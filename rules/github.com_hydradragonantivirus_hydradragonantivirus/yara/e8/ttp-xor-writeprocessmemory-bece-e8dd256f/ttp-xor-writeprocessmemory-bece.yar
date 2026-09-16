rule TTP_XOR_WriteProcessMemory_bece {
  strings:
    $key_bece = { e9 bc [2] db 9e [2] dd ab [2] f3 ab [2] cc b7 }

  condition:
    any of them
}