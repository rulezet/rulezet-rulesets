rule TTP_XOR_WriteProcessMemory_5828 {
  strings:
    $key_5828 = { 0f 5a [2] 3d 78 [2] 3b 4d [2] 15 4d [2] 2a 51 }

  condition:
    any of them
}