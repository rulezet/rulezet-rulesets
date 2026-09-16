rule TTP_XOR_WriteProcessMemory_6a40 {
  strings:
    $key_6a40 = { 3d 32 [2] 0f 10 [2] 09 25 [2] 27 25 [2] 18 39 }

  condition:
    any of them
}