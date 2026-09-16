rule TTP_XOR_WriteProcessMemory_0158 {
  strings:
    $key_0158 = { 56 2a [2] 64 08 [2] 62 3d [2] 4c 3d [2] 73 21 }

  condition:
    any of them
}