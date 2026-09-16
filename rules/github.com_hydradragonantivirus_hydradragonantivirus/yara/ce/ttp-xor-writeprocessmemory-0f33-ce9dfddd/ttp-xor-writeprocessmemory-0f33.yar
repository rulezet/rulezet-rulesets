rule TTP_XOR_WriteProcessMemory_0f33 {
  strings:
    $key_0f33 = { 58 41 [2] 6a 63 [2] 6c 56 [2] 42 56 [2] 7d 4a }

  condition:
    any of them
}