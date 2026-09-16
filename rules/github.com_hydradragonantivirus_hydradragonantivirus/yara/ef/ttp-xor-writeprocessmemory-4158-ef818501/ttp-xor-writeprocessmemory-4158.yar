rule TTP_XOR_WriteProcessMemory_4158 {
  strings:
    $key_4158 = { 16 2a [2] 24 08 [2] 22 3d [2] 0c 3d [2] 33 21 }

  condition:
    any of them
}