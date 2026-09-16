rule TTP_XOR_WriteProcessMemory_3fe4 {
  strings:
    $key_3fe4 = { 68 96 [2] 5a b4 [2] 5c 81 [2] 72 81 [2] 4d 9d }

  condition:
    any of them
}