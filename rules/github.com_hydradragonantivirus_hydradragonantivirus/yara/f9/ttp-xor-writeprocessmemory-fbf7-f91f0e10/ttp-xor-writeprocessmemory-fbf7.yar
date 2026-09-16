rule TTP_XOR_WriteProcessMemory_fbf7 {
  strings:
    $key_fbf7 = { ac 85 [2] 9e a7 [2] 98 92 [2] b6 92 [2] 89 8e }

  condition:
    any of them
}