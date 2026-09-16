rule TTP_XOR_WriteProcessMemory_0f6d {
  strings:
    $key_0f6d = { 58 1f [2] 6a 3d [2] 6c 08 [2] 42 08 [2] 7d 14 }

  condition:
    any of them
}