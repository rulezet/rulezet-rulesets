rule TTP_XOR_WriteProcessMemory_7cf3 {
  strings:
    $key_7cf3 = { 2b 81 [2] 19 a3 [2] 1f 96 [2] 31 96 [2] 0e 8a }

  condition:
    any of them
}