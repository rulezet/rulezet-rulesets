rule TTP_XOR_WriteProcessMemory_bfd8 {
  strings:
    $key_bfd8 = { e8 aa [2] da 88 [2] dc bd [2] f2 bd [2] cd a1 }

  condition:
    any of them
}