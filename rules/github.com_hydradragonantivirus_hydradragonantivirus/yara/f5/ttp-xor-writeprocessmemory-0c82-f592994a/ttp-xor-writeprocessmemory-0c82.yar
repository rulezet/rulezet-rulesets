rule TTP_XOR_WriteProcessMemory_0c82 {
  strings:
    $key_0c82 = { 5b f0 [2] 69 d2 [2] 6f e7 [2] 41 e7 [2] 7e fb }

  condition:
    any of them
}