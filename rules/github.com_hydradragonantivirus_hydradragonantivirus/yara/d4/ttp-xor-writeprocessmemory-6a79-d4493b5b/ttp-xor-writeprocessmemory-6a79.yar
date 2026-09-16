rule TTP_XOR_WriteProcessMemory_6a79 {
  strings:
    $key_6a79 = { 3d 0b [2] 0f 29 [2] 09 1c [2] 27 1c [2] 18 00 }

  condition:
    any of them
}