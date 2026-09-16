rule TTP_XOR_WriteProcessMemory_64f4 {
  strings:
    $key_64f4 = { 33 86 [2] 01 a4 [2] 07 91 [2] 29 91 [2] 16 8d }

  condition:
    any of them
}