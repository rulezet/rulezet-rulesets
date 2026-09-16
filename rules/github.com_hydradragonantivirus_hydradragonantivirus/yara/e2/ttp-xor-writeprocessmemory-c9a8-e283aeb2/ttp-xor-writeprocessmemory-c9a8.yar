rule TTP_XOR_WriteProcessMemory_c9a8 {
  strings:
    $key_c9a8 = { 9e da [2] ac f8 [2] aa cd [2] 84 cd [2] bb d1 }

  condition:
    any of them
}