rule TTP_XOR_WriteProcessMemory_e366 {
  strings:
    $key_e366 = { b4 14 [2] 86 36 [2] 80 03 [2] ae 03 [2] 91 1f }

  condition:
    any of them
}