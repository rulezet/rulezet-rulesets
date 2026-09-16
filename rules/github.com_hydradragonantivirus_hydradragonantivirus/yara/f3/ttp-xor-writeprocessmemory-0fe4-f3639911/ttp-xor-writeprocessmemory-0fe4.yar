rule TTP_XOR_WriteProcessMemory_0fe4 {
  strings:
    $key_0fe4 = { 58 96 [2] 6a b4 [2] 6c 81 [2] 42 81 [2] 7d 9d }

  condition:
    any of them
}