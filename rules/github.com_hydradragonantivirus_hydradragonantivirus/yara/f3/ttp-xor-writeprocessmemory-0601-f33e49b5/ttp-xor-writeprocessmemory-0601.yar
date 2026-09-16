rule TTP_XOR_WriteProcessMemory_0601 {
  strings:
    $key_0601 = { 51 73 [2] 63 51 [2] 65 64 [2] 4b 64 [2] 74 78 }

  condition:
    any of them
}