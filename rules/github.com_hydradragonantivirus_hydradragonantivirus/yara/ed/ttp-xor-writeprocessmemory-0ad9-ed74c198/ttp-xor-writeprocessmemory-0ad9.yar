rule TTP_XOR_WriteProcessMemory_0ad9 {
  strings:
    $key_0ad9 = { 5d ab [2] 6f 89 [2] 69 bc [2] 47 bc [2] 78 a0 }

  condition:
    any of them
}