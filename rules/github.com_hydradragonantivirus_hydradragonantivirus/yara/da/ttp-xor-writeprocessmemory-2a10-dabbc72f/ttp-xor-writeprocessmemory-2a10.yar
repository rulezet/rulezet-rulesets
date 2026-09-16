rule TTP_XOR_WriteProcessMemory_2a10 {
  strings:
    $key_2a10 = { 7d 62 [2] 4f 40 [2] 49 75 [2] 67 75 [2] 58 69 }

  condition:
    any of them
}