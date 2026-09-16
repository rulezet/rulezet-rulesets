rule TTP_XOR_WriteProcessMemory_2193 {
  strings:
    $key_2193 = { 76 e1 [2] 44 c3 [2] 42 f6 [2] 6c f6 [2] 53 ea }

  condition:
    any of them
}