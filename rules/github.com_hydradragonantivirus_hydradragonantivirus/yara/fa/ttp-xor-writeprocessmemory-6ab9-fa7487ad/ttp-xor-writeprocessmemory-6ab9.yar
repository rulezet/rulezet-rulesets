rule TTP_XOR_WriteProcessMemory_6ab9 {
  strings:
    $key_6ab9 = { 3d cb [2] 0f e9 [2] 09 dc [2] 27 dc [2] 18 c0 }

  condition:
    any of them
}