rule TTP_XOR_WriteProcessMemory_0193 {
  strings:
    $key_0193 = { 56 e1 [2] 64 c3 [2] 62 f6 [2] 4c f6 [2] 73 ea }

  condition:
    any of them
}