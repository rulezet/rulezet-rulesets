rule TTP_XOR_WriteProcessMemory_bf55 {
  strings:
    $key_bf55 = { e8 27 [2] da 05 [2] dc 30 [2] f2 30 [2] cd 2c }

  condition:
    any of them
}