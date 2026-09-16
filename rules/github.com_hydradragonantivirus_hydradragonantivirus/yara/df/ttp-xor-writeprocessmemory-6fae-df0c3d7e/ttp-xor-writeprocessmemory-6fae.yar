rule TTP_XOR_WriteProcessMemory_6fae {
  strings:
    $key_6fae = { 38 dc [2] 0a fe [2] 0c cb [2] 22 cb [2] 1d d7 }

  condition:
    any of them
}