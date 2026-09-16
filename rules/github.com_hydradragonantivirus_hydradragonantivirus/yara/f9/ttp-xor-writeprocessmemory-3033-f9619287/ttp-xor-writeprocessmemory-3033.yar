rule TTP_XOR_WriteProcessMemory_3033 {
  strings:
    $key_3033 = { 67 41 [2] 55 63 [2] 53 56 [2] 7d 56 [2] 42 4a }

  condition:
    any of them
}