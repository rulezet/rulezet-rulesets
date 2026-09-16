rule TTP_XOR_WriteProcessMemory_7d93 {
  strings:
    $key_7d93 = { 2a e1 [2] 18 c3 [2] 1e f6 [2] 30 f6 [2] 0f ea }

  condition:
    any of them
}