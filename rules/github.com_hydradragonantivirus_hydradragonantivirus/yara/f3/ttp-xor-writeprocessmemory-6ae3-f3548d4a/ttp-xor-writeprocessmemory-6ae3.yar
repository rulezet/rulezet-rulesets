rule TTP_XOR_WriteProcessMemory_6ae3 {
  strings:
    $key_6ae3 = { 3d 91 [2] 0f b3 [2] 09 86 [2] 27 86 [2] 18 9a }

  condition:
    any of them
}