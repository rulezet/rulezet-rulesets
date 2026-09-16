rule TTP_XOR_WriteProcessMemory_0a67 {
  strings:
    $key_0a67 = { 5d 15 [2] 6f 37 [2] 69 02 [2] 47 02 [2] 78 1e }

  condition:
    any of them
}