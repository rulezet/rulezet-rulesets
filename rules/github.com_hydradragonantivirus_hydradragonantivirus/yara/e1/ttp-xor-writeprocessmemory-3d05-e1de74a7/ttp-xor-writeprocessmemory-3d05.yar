rule TTP_XOR_WriteProcessMemory_3d05 {
  strings:
    $key_3d05 = { 6a 77 [2] 58 55 [2] 5e 60 [2] 70 60 [2] 4f 7c }

  condition:
    any of them
}