rule TTP_XOR_WriteProcessMemory_5fe4 {
  strings:
    $key_5fe4 = { 08 96 [2] 3a b4 [2] 3c 81 [2] 12 81 [2] 2d 9d }

  condition:
    any of them
}