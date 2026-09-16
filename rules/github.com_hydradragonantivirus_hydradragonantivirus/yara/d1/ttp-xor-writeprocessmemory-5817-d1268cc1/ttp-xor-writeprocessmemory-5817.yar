rule TTP_XOR_WriteProcessMemory_5817 {
  strings:
    $key_5817 = { 0f 65 [2] 3d 47 [2] 3b 72 [2] 15 72 [2] 2a 6e }

  condition:
    any of them
}