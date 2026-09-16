rule TTP_XOR_WriteProcessMemory_0bf4 {
  strings:
    $key_0bf4 = { 5c 86 [2] 6e a4 [2] 68 91 [2] 46 91 [2] 79 8d }

  condition:
    any of them
}