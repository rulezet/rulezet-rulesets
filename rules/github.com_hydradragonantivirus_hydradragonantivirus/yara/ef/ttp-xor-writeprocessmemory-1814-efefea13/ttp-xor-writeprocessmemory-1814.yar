rule TTP_XOR_WriteProcessMemory_1814 {
  strings:
    $key_1814 = { 4f 66 [2] 7d 44 [2] 7b 71 [2] 55 71 [2] 6a 6d }

  condition:
    any of them
}