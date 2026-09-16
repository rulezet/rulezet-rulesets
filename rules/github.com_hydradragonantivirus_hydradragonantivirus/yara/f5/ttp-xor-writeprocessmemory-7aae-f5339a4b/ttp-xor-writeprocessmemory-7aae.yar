rule TTP_XOR_WriteProcessMemory_7aae {
  strings:
    $key_7aae = { 2d dc [2] 1f fe [2] 19 cb [2] 37 cb [2] 08 d7 }

  condition:
    any of them
}