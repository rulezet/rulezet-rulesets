rule TTP_XOR_WriteProcessMemory_dfae {
  strings:
    $key_dfae = { 88 dc [2] ba fe [2] bc cb [2] 92 cb [2] ad d7 }

  condition:
    any of them
}