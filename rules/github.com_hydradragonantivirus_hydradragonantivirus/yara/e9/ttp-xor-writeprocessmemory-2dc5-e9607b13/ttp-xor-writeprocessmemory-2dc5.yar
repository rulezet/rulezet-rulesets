rule TTP_XOR_WriteProcessMemory_2dc5 {
  strings:
    $key_2dc5 = { 7a b7 [2] 48 95 [2] 4e a0 [2] 60 a0 [2] 5f bc }

  condition:
    any of them
}