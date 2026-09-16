rule TTP_XOR_WriteProcessMemory_bfc8 {
  strings:
    $key_bfc8 = { e8 ba [2] da 98 [2] dc ad [2] f2 ad [2] cd b1 }

  condition:
    any of them
}