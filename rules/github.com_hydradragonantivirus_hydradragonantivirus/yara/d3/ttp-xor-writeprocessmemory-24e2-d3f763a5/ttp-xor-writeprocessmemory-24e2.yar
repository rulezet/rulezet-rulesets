rule TTP_XOR_WriteProcessMemory_24e2 {
  strings:
    $key_24e2 = { 73 90 [2] 41 b2 [2] 47 87 [2] 69 87 [2] 56 9b }

  condition:
    any of them
}