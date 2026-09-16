rule TTP_XOR_WriteProcessMemory_bfb5 {
  strings:
    $key_bfb5 = { e8 c7 [2] da e5 [2] dc d0 [2] f2 d0 [2] cd cc }

  condition:
    any of them
}