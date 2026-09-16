rule TTP_XOR_WriteProcessMemory_6a20 {
  strings:
    $key_6a20 = { 3d 52 [2] 0f 70 [2] 09 45 [2] 27 45 [2] 18 59 }

  condition:
    any of them
}