rule TTP_XOR_WriteProcessMemory_6dae {
  strings:
    $key_6dae = { 3a dc [2] 08 fe [2] 0e cb [2] 20 cb [2] 1f d7 }

  condition:
    any of them
}