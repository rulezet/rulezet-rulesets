rule TTP_XOR_WriteProcessMemory_259b {
  strings:
    $key_259b = { 72 e9 [2] 40 cb [2] 46 fe [2] 68 fe [2] 57 e2 }

  condition:
    any of them
}