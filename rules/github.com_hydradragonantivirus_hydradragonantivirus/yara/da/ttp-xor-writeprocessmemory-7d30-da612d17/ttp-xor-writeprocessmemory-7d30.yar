rule TTP_XOR_WriteProcessMemory_7d30 {
  strings:
    $key_7d30 = { 2a 42 [2] 18 60 [2] 1e 55 [2] 30 55 [2] 0f 49 }

  condition:
    any of them
}