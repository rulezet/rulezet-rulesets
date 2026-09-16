rule TTP_XOR_WriteProcessMemory_26f0 {
  strings:
    $key_26f0 = { 71 82 [2] 43 a0 [2] 45 95 [2] 6b 95 [2] 54 89 }

  condition:
    any of them
}