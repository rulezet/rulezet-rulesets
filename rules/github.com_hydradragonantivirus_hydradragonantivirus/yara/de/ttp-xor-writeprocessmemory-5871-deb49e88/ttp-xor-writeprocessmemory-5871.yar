rule TTP_XOR_WriteProcessMemory_5871 {
  strings:
    $key_5871 = { 0f 03 [2] 3d 21 [2] 3b 14 [2] 15 14 [2] 2a 08 }

  condition:
    any of them
}