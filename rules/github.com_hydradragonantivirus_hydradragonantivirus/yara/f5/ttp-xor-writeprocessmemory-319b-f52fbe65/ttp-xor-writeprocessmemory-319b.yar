rule TTP_XOR_WriteProcessMemory_319b {
  strings:
    $key_319b = { 66 e9 [2] 54 cb [2] 52 fe [2] 7c fe [2] 43 e2 }

  condition:
    any of them
}