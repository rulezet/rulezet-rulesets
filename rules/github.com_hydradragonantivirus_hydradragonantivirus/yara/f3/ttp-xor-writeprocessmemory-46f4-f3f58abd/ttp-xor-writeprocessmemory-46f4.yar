rule TTP_XOR_WriteProcessMemory_46f4 {
  strings:
    $key_46f4 = { 11 86 [2] 23 a4 [2] 25 91 [2] 0b 91 [2] 34 8d }

  condition:
    any of them
}