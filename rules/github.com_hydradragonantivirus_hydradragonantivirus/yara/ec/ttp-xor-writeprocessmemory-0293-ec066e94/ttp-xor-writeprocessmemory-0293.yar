rule TTP_XOR_WriteProcessMemory_0293 {
  strings:
    $key_0293 = { 55 e1 [2] 67 c3 [2] 61 f6 [2] 4f f6 [2] 70 ea }

  condition:
    any of them
}