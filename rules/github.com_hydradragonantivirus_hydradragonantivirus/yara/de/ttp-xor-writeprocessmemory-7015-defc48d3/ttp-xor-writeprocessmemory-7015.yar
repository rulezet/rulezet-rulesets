rule TTP_XOR_WriteProcessMemory_7015 {
  strings:
    $key_7015 = { 27 67 [2] 15 45 [2] 13 70 [2] 3d 70 [2] 02 6c }

  condition:
    any of them
}