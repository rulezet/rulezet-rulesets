rule TTP_XOR_WriteProcessMemory_46e3 {
  strings:
    $key_46e3 = { 11 91 [2] 23 b3 [2] 25 86 [2] 0b 86 [2] 34 9a }

  condition:
    any of them
}