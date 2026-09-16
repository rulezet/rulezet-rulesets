rule TTP_XOR_WriteProcessMemory_4aae {
  strings:
    $key_4aae = { 1d dc [2] 2f fe [2] 29 cb [2] 07 cb [2] 38 d7 }

  condition:
    any of them
}