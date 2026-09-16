rule TTP_XOR_WriteProcessMemory_73f4 {
  strings:
    $key_73f4 = { 24 86 [2] 16 a4 [2] 10 91 [2] 3e 91 [2] 01 8d }

  condition:
    any of them
}