rule TTP_XOR_WriteProcessMemory_7011 {
  strings:
    $key_7011 = { 27 63 [2] 15 41 [2] 13 74 [2] 3d 74 [2] 02 68 }

  condition:
    any of them
}