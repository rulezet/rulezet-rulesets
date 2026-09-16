rule TTP_XOR_WriteProcessMemory_7004 {
  strings:
    $key_7004 = { 27 76 [2] 15 54 [2] 13 61 [2] 3d 61 [2] 02 7d }

  condition:
    any of them
}