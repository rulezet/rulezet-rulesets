rule TTP_XOR_WriteProcessMemory_5cea {
  strings:
    $key_5cea = { 0b 98 [2] 39 ba [2] 3f 8f [2] 11 8f [2] 2e 93 }

  condition:
    any of them
}