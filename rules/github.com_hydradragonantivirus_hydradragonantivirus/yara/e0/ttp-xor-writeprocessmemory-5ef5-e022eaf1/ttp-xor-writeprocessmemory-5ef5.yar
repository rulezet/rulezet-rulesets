rule TTP_XOR_WriteProcessMemory_5ef5 {
  strings:
    $key_5ef5 = { 09 87 [2] 3b a5 [2] 3d 90 [2] 13 90 [2] 2c 8c }

  condition:
    any of them
}