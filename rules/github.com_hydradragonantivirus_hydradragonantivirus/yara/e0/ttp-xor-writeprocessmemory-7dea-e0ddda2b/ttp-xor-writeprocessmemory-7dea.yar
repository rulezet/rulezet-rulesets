rule TTP_XOR_WriteProcessMemory_7dea {
  strings:
    $key_7dea = { 2a 98 [2] 18 ba [2] 1e 8f [2] 30 8f [2] 0f 93 }

  condition:
    any of them
}