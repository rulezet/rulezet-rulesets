rule TTP_XOR_WriteProcessMemory_b2b9 {
  strings:
    $key_b2b9 = { e5 cb [2] d7 e9 [2] d1 dc [2] ff dc [2] c0 c0 }

  condition:
    any of them
}