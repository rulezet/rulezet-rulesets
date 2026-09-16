rule TTP_XOR_WriteProcessMemory_6c44 {
  strings:
    $key_6c44 = { 3b 36 [2] 09 14 [2] 0f 21 [2] 21 21 [2] 1e 3d }

  condition:
    any of them
}