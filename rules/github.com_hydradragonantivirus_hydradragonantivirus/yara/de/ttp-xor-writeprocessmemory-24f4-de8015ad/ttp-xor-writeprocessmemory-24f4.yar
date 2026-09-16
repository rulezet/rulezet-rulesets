rule TTP_XOR_WriteProcessMemory_24f4 {
  strings:
    $key_24f4 = { 73 86 [2] 41 a4 [2] 47 91 [2] 69 91 [2] 56 8d }

  condition:
    any of them
}