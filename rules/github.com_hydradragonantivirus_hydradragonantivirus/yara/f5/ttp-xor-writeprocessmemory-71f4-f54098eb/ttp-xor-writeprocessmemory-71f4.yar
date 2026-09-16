rule TTP_XOR_WriteProcessMemory_71f4 {
  strings:
    $key_71f4 = { 26 86 [2] 14 a4 [2] 12 91 [2] 3c 91 [2] 03 8d }

  condition:
    any of them
}