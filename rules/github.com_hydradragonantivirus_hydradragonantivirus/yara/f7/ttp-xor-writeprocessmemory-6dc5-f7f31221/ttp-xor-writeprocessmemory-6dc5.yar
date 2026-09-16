rule TTP_XOR_WriteProcessMemory_6dc5 {
  strings:
    $key_6dc5 = { 3a b7 [2] 08 95 [2] 0e a0 [2] 20 a0 [2] 1f bc }

  condition:
    any of them
}