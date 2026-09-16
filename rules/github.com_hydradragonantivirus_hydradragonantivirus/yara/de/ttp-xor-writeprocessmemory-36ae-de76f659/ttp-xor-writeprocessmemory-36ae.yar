rule TTP_XOR_WriteProcessMemory_36ae {
  strings:
    $key_36ae = { 61 dc [2] 53 fe [2] 55 cb [2] 7b cb [2] 44 d7 }

  condition:
    any of them
}