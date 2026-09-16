rule TTP_XOR_WriteProcessMemory_0a65 {
  strings:
    $key_0a65 = { 5d 17 [2] 6f 35 [2] 69 00 [2] 47 00 [2] 78 1c }

  condition:
    any of them
}