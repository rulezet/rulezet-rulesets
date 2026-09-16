rule TTP_XOR_WriteProcessMemory_ccae {
  strings:
    $key_ccae = { 9b dc [2] a9 fe [2] af cb [2] 81 cb [2] be d7 }

  condition:
    any of them
}