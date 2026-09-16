rule TTP_XOR_WriteProcessMemory_26f1 {
  strings:
    $key_26f1 = { 71 83 [2] 43 a1 [2] 45 94 [2] 6b 94 [2] 54 88 }

  condition:
    any of them
}