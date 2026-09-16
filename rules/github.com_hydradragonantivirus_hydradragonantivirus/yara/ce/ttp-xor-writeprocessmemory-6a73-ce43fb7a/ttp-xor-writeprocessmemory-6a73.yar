rule TTP_XOR_WriteProcessMemory_6a73 {
  strings:
    $key_6a73 = { 3d 01 [2] 0f 23 [2] 09 16 [2] 27 16 [2] 18 0a }

  condition:
    any of them
}