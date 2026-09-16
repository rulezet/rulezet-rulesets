rule TTP_XOR_WriteProcessMemory_5892 {
  strings:
    $key_5892 = { 0f e0 [2] 3d c2 [2] 3b f7 [2] 15 f7 [2] 2a eb }

  condition:
    any of them
}