rule TTP_XOR_WriteProcessMemory_5001 {
  strings:
    $key_5001 = { 07 73 [2] 35 51 [2] 33 64 [2] 1d 64 [2] 22 78 }

  condition:
    any of them
}