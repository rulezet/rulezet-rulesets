rule TTP_XOR_WriteProcessMemory_049b {
  strings:
    $key_049b = { 53 e9 [2] 61 cb [2] 67 fe [2] 49 fe [2] 76 e2 }

  condition:
    any of them
}