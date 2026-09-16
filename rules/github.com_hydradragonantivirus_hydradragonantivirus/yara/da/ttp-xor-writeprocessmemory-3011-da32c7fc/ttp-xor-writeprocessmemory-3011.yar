rule TTP_XOR_WriteProcessMemory_3011 {
  strings:
    $key_3011 = { 67 63 [2] 55 41 [2] 53 74 [2] 7d 74 [2] 42 68 }

  condition:
    any of them
}