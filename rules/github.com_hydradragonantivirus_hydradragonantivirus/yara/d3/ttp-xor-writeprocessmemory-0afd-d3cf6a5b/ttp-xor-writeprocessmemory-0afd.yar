rule TTP_XOR_WriteProcessMemory_0afd {
  strings:
    $key_0afd = { 5d 8f [2] 6f ad [2] 69 98 [2] 47 98 [2] 78 84 }

  condition:
    any of them
}