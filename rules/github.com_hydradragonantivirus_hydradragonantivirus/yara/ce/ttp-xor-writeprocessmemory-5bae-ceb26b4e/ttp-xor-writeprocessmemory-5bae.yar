rule TTP_XOR_WriteProcessMemory_5bae {
  strings:
    $key_5bae = { 0c dc [2] 3e fe [2] 38 cb [2] 16 cb [2] 29 d7 }

  condition:
    any of them
}