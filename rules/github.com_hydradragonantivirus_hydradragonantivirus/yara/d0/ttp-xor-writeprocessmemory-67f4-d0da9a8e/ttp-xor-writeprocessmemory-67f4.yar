rule TTP_XOR_WriteProcessMemory_67f4 {
  strings:
    $key_67f4 = { 30 86 [2] 02 a4 [2] 04 91 [2] 2a 91 [2] 15 8d }

  condition:
    any of them
}