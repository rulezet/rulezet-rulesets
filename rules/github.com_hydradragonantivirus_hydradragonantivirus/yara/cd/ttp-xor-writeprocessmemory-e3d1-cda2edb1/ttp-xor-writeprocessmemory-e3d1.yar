rule TTP_XOR_WriteProcessMemory_e3d1 {
  strings:
    $key_e3d1 = { b4 a3 [2] 86 81 [2] 80 b4 [2] ae b4 [2] 91 a8 }

  condition:
    any of them
}