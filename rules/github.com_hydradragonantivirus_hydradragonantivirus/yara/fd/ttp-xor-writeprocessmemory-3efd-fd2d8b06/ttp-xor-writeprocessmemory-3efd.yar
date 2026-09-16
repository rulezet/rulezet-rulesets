rule TTP_XOR_WriteProcessMemory_3efd {
  strings:
    $key_3efd = { 69 8f [2] 5b ad [2] 5d 98 [2] 73 98 [2] 4c 84 }

  condition:
    any of them
}