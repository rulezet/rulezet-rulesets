rule TTP_XOR_WriteProcessMemory_5344 {
  strings:
    $key_5344 = { 04 36 [2] 36 14 [2] 30 21 [2] 1e 21 [2] 21 3d }

  condition:
    any of them
}