rule TTP_XOR_WriteProcessMemory_bfc6 {
  strings:
    $key_bfc6 = { e8 b4 [2] da 96 [2] dc a3 [2] f2 a3 [2] cd bf }

  condition:
    any of them
}