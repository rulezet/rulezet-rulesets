rule TTP_XOR_WriteProcessMemory_68ae {
  strings:
    $key_68ae = { 3f dc [2] 0d fe [2] 0b cb [2] 25 cb [2] 1a d7 }

  condition:
    any of them
}