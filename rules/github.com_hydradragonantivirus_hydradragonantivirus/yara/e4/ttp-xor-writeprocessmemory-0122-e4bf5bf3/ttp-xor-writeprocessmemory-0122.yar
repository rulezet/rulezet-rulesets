rule TTP_XOR_WriteProcessMemory_0122 {
  strings:
    $key_0122 = { 56 50 [2] 64 72 [2] 62 47 [2] 4c 47 [2] 73 5b }

  condition:
    any of them
}