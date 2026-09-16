rule TTP_XOR_WriteProcessMemory_0139 {
  strings:
    $key_0139 = { 56 4b [2] 64 69 [2] 62 5c [2] 4c 5c [2] 73 40 }

  condition:
    any of them
}