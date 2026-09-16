rule TTP_XOR_WriteProcessMemory_6f01 {
  strings:
    $key_6f01 = { 38 73 [2] 0a 51 [2] 0c 64 [2] 22 64 [2] 1d 78 }

  condition:
    any of them
}