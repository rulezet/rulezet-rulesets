rule TTP_XOR_WriteProcessMemory_4cea {
  strings:
    $key_4cea = { 1b 98 [2] 29 ba [2] 2f 8f [2] 01 8f [2] 3e 93 }

  condition:
    any of them
}