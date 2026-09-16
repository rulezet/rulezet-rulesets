rule TTP_XOR_WriteProcessMemory_fbfd {
  strings:
    $key_fbfd = { ac 8f [2] 9e ad [2] 98 98 [2] b6 98 [2] 89 84 }

  condition:
    any of them
}