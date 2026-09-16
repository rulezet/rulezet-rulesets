rule TTP_XOR_WriteProcessMemory_3024 {
  strings:
    $key_3024 = { 67 56 [2] 55 74 [2] 53 41 [2] 7d 41 [2] 42 5d }

  condition:
    any of them
}