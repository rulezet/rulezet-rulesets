rule TTP_XOR_WriteProcessMemory_9dae {
  strings:
    $key_9dae = { ca dc [2] f8 fe [2] fe cb [2] d0 cb [2] ef d7 }

  condition:
    any of them
}