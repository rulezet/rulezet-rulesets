rule TTP_XOR_WriteProcessMemory_4c44 {
  strings:
    $key_4c44 = { 1b 36 [2] 29 14 [2] 2f 21 [2] 01 21 [2] 3e 3d }

  condition:
    any of them
}