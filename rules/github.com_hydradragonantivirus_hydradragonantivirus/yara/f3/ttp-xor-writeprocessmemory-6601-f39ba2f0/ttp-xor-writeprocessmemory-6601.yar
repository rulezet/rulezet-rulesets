rule TTP_XOR_WriteProcessMemory_6601 {
  strings:
    $key_6601 = { 31 73 [2] 03 51 [2] 05 64 [2] 2b 64 [2] 14 78 }

  condition:
    any of them
}