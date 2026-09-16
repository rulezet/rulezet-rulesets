rule TTP_XOR_WriteProcessMemory_6efd {
  strings:
    $key_6efd = { 39 8f [2] 0b ad [2] 0d 98 [2] 23 98 [2] 1c 84 }

  condition:
    any of them
}