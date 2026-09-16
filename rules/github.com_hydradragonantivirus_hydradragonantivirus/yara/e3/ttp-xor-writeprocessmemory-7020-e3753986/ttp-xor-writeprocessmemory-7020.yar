rule TTP_XOR_WriteProcessMemory_7020 {
  strings:
    $key_7020 = { 27 52 [2] 15 70 [2] 13 45 [2] 3d 45 [2] 02 59 }

  condition:
    any of them
}