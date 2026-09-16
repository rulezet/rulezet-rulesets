rule TTP_XOR_WriteProcessMemory_1836 {
  strings:
    $key_1836 = { 4f 44 [2] 7d 66 [2] 7b 53 [2] 55 53 [2] 6a 4f }

  condition:
    any of them
}