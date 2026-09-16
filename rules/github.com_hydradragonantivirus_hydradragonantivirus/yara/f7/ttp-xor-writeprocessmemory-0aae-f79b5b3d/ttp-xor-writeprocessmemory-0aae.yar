rule TTP_XOR_WriteProcessMemory_0aae {
  strings:
    $key_0aae = { 5d dc [2] 6f fe [2] 69 cb [2] 47 cb [2] 78 d7 }

  condition:
    any of them
}