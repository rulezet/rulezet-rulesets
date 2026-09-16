rule TTP_XOR_WriteProcessMemory_ea6d {
  strings:
    $key_ea6d = { bd 1f [2] 8f 3d [2] 89 08 [2] a7 08 [2] 98 14 }

  condition:
    any of them
}