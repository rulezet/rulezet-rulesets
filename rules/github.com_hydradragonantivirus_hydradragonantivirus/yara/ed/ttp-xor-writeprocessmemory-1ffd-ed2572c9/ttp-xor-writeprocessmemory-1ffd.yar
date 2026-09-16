rule TTP_XOR_WriteProcessMemory_1ffd {
  strings:
    $key_1ffd = { 48 8f [2] 7a ad [2] 7c 98 [2] 52 98 [2] 6d 84 }

  condition:
    any of them
}