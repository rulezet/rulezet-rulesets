rule TTP_XOR_WriteProcessMemory_269b {
  strings:
    $key_269b = { 71 e9 [2] 43 cb [2] 45 fe [2] 6b fe [2] 54 e2 }

  condition:
    any of them
}