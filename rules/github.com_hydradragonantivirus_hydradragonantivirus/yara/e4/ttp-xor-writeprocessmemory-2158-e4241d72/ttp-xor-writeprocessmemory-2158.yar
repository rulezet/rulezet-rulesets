rule TTP_XOR_WriteProcessMemory_2158 {
  strings:
    $key_2158 = { 76 2a [2] 44 08 [2] 42 3d [2] 6c 3d [2] 53 21 }

  condition:
    any of them
}