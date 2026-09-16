rule TTP_XOR_WriteProcessMemory_5158 {
  strings:
    $key_5158 = { 06 2a [2] 34 08 [2] 32 3d [2] 1c 3d [2] 23 21 }

  condition:
    any of them
}