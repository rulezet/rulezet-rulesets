rule TTP_XOR_WriteProcessMemory_e8ae {
  strings:
    $key_e8ae = { bf dc [2] 8d fe [2] 8b cb [2] a5 cb [2] 9a d7 }

  condition:
    any of them
}