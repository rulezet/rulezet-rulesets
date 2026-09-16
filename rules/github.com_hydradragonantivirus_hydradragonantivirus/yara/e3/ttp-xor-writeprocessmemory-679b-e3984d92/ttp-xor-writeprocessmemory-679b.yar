rule TTP_XOR_WriteProcessMemory_679b {
  strings:
    $key_679b = { 30 e9 [2] 02 cb [2] 04 fe [2] 2a fe [2] 15 e2 }

  condition:
    any of them
}