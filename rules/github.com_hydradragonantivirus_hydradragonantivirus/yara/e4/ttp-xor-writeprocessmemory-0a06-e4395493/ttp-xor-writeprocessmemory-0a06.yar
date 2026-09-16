rule TTP_XOR_WriteProcessMemory_0a06 {
  strings:
    $key_0a06 = { 5d 74 [2] 6f 56 [2] 69 63 [2] 47 63 [2] 78 7f }

  condition:
    any of them
}