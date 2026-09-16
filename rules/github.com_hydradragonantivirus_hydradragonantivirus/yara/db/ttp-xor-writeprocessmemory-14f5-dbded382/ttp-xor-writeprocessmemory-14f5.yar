rule TTP_XOR_WriteProcessMemory_14f5 {
  strings:
    $key_14f5 = { 43 87 [2] 71 a5 [2] 77 90 [2] 59 90 [2] 66 8c }

  condition:
    any of them
}