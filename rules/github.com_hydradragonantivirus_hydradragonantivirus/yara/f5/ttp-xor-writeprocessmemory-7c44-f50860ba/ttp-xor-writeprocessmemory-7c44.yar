rule TTP_XOR_WriteProcessMemory_7c44 {
  strings:
    $key_7c44 = { 2b 36 [2] 19 14 [2] 1f 21 [2] 31 21 [2] 0e 3d }

  condition:
    any of them
}