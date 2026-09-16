rule TTP_XOR_WriteProcessMemory_12f4 {
  strings:
    $key_12f4 = { 45 86 [2] 77 a4 [2] 71 91 [2] 5f 91 [2] 60 8d }

  condition:
    any of them
}