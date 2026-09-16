rule TTP_XOR_WriteProcessMemory_2aae {
  strings:
    $key_2aae = { 7d dc [2] 4f fe [2] 49 cb [2] 67 cb [2] 58 d7 }

  condition:
    any of them
}