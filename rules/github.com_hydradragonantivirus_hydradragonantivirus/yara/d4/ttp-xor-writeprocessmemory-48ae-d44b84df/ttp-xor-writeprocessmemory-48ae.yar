rule TTP_XOR_WriteProcessMemory_48ae {
  strings:
    $key_48ae = { 1f dc [2] 2d fe [2] 2b cb [2] 05 cb [2] 3a d7 }

  condition:
    any of them
}