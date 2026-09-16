rule TTP_XOR_WriteProcessMemory_0169 {
  strings:
    $key_0169 = { 56 1b [2] 64 39 [2] 62 0c [2] 4c 0c [2] 73 10 }

  condition:
    any of them
}