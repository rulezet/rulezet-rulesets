rule TTP_XOR_WriteProcessMemory_ee8c {
  strings:
    $key_ee8c = { b9 fe [2] 8b dc [2] 8d e9 [2] a3 e9 [2] 9c f5 }

  condition:
    any of them
}