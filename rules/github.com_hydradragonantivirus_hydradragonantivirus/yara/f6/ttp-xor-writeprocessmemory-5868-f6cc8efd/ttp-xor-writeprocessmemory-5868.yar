rule TTP_XOR_WriteProcessMemory_5868 {
  strings:
    $key_5868 = { 0f 1a [2] 3d 38 [2] 3b 0d [2] 15 0d [2] 2a 11 }

  condition:
    any of them
}