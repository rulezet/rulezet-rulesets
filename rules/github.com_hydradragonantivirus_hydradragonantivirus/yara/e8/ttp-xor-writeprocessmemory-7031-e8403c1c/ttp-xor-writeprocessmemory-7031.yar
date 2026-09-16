rule TTP_XOR_WriteProcessMemory_7031 {
  strings:
    $key_7031 = { 27 43 [2] 15 61 [2] 13 54 [2] 3d 54 [2] 02 48 }

  condition:
    any of them
}