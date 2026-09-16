rule TTP_XOR_WriteProcessMemory_0133 {
  strings:
    $key_0133 = { 56 41 [2] 64 63 [2] 62 56 [2] 4c 56 [2] 73 4a }

  condition:
    any of them
}