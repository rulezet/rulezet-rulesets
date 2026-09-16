rule TTP_XOR_WriteProcessMemory_bfce {
  strings:
    $key_bfce = { e8 bc [2] da 9e [2] dc ab [2] f2 ab [2] cd b7 }

  condition:
    any of them
}