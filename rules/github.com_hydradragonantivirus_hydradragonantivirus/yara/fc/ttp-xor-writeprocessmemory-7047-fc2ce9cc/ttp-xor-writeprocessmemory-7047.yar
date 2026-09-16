rule TTP_XOR_WriteProcessMemory_7047 {
  strings:
    $key_7047 = { 27 35 [2] 15 17 [2] 13 22 [2] 3d 22 [2] 02 3e }

  condition:
    any of them
}