rule TTP_XOR_WriteProcessMemory_fbf4 {
  strings:
    $key_fbf4 = { ac 86 [2] 9e a4 [2] 98 91 [2] b6 91 [2] 89 8d }

  condition:
    any of them
}