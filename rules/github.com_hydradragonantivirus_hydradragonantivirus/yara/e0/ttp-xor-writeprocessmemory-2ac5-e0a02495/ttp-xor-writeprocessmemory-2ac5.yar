rule TTP_XOR_WriteProcessMemory_2ac5 {
  strings:
    $key_2ac5 = { 7d b7 [2] 4f 95 [2] 49 a0 [2] 67 a0 [2] 58 bc }

  condition:
    any of them
}