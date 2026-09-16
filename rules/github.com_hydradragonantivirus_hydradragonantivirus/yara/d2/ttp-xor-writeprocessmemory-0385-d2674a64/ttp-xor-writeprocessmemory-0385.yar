rule TTP_XOR_WriteProcessMemory_0385 {
  strings:
    $key_0385 = { 54 f7 [2] 66 d5 [2] 60 e0 [2] 4e e0 [2] 71 fc }

  condition:
    any of them
}