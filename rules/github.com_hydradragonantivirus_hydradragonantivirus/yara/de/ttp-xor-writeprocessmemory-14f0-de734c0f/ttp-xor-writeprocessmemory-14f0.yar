rule TTP_XOR_WriteProcessMemory_14f0 {
  strings:
    $key_14f0 = { 43 82 [2] 71 a0 [2] 77 95 [2] 59 95 [2] 66 89 }

  condition:
    any of them
}