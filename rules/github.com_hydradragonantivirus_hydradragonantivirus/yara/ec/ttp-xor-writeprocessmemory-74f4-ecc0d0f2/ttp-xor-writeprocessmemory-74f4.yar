rule TTP_XOR_WriteProcessMemory_74f4 {
  strings:
    $key_74f4 = { 23 86 [2] 11 a4 [2] 17 91 [2] 39 91 [2] 06 8d }

  condition:
    any of them
}