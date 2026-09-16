rule TTP_XOR_WriteProcessMemory_1dc5 {
  strings:
    $key_1dc5 = { 4a b7 [2] 78 95 [2] 7e a0 [2] 50 a0 [2] 6f bc }

  condition:
    any of them
}