rule TTP_XOR_WriteProcessMemory_27f4 {
  strings:
    $key_27f4 = { 70 86 [2] 42 a4 [2] 44 91 [2] 6a 91 [2] 55 8d }

  condition:
    any of them
}