rule TTP_XOR_WriteProcessMemory_3cd7 {
  strings:
    $key_3cd7 = { 6b a5 [2] 59 87 [2] 5f b2 [2] 71 b2 [2] 4e ae }

  condition:
    any of them
}