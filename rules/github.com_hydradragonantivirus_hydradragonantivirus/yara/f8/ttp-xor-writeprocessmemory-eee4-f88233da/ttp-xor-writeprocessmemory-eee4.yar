rule TTP_XOR_WriteProcessMemory_eee4 {
  strings:
    $key_eee4 = { b9 96 [2] 8b b4 [2] 8d 81 [2] a3 81 [2] 9c 9d }

  condition:
    any of them
}