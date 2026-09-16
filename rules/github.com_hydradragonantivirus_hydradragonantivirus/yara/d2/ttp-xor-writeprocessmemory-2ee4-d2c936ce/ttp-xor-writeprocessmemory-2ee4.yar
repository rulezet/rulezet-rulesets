rule TTP_XOR_WriteProcessMemory_2ee4 {
  strings:
    $key_2ee4 = { 79 96 [2] 4b b4 [2] 4d 81 [2] 63 81 [2] 5c 9d }

  condition:
    any of them
}