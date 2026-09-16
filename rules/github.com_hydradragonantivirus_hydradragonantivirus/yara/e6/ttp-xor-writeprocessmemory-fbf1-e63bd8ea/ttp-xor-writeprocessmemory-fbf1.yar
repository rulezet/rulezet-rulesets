rule TTP_XOR_WriteProcessMemory_fbf1 {
  strings:
    $key_fbf1 = { ac 83 [2] 9e a1 [2] 98 94 [2] b6 94 [2] 89 88 }

  condition:
    any of them
}