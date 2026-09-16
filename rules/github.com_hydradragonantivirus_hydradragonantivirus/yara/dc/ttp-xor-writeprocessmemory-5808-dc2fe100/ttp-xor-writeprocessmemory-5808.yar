rule TTP_XOR_WriteProcessMemory_5808 {
  strings:
    $key_5808 = { 0f 7a [2] 3d 58 [2] 3b 6d [2] 15 6d [2] 2a 71 }

  condition:
    any of them
}