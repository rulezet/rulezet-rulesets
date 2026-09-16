rule TTP_XOR_WriteProcessMemory_26f8 {
  strings:
    $key_26f8 = { 71 8a [2] 43 a8 [2] 45 9d [2] 6b 9d [2] 54 81 }

  condition:
    any of them
}