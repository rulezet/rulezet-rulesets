rule TTP_XOR_WriteProcessMemory_fbf5 {
  strings:
    $key_fbf5 = { ac 87 [2] 9e a5 [2] 98 90 [2] b6 90 [2] 89 8c }

  condition:
    any of them
}