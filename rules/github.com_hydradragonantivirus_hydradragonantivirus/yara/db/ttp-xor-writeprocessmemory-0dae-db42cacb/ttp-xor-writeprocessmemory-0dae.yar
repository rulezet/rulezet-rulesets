rule TTP_XOR_WriteProcessMemory_0dae {
  strings:
    $key_0dae = { 5a dc [2] 68 fe [2] 6e cb [2] 40 cb [2] 7f d7 }

  condition:
    any of them
}