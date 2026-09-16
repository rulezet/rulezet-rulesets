rule TTP_XOR_WriteProcessMemory_26f3 {
  strings:
    $key_26f3 = { 71 81 [2] 43 a3 [2] 45 96 [2] 6b 96 [2] 54 8a }

  condition:
    any of them
}