rule TTP_XOR_WriteProcessMemory_4f19 {
  strings:
    $key_4f19 = { 18 6b [2] 2a 49 [2] 2c 7c [2] 02 7c [2] 3d 60 }

  condition:
    any of them
}