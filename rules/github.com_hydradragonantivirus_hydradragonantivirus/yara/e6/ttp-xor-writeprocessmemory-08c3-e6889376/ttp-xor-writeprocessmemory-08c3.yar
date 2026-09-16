rule TTP_XOR_WriteProcessMemory_08c3 {
  strings:
    $key_08c3 = { 5f b1 [2] 6d 93 [2] 6b a6 [2] 45 a6 [2] 7a ba }

  condition:
    any of them
}