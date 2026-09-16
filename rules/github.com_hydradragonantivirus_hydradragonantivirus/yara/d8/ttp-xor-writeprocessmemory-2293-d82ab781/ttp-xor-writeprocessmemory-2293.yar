rule TTP_XOR_WriteProcessMemory_2293 {
  strings:
    $key_2293 = { 75 e1 [2] 47 c3 [2] 41 f6 [2] 6f f6 [2] 50 ea }

  condition:
    any of them
}