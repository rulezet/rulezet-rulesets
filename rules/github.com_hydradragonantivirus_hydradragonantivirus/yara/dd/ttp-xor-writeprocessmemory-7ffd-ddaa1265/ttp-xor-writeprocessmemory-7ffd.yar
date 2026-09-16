rule TTP_XOR_WriteProcessMemory_7ffd {
  strings:
    $key_7ffd = { 28 8f [2] 1a ad [2] 1c 98 [2] 32 98 [2] 0d 84 }

  condition:
    any of them
}