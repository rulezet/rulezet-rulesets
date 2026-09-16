rule TTP_XOR_WriteProcessMemory_ccc5 {
  strings:
    $key_ccc5 = { 9b b7 [2] a9 95 [2] af a0 [2] 81 a0 [2] be bc }

  condition:
    any of them
}