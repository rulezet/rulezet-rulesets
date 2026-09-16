rule TTP_XOR_WriteProcessMemory_6cf2 {
  strings:
    $key_6cf2 = { 3b 80 [2] 09 a2 [2] 0f 97 [2] 21 97 [2] 1e 8b }

  condition:
    any of them
}