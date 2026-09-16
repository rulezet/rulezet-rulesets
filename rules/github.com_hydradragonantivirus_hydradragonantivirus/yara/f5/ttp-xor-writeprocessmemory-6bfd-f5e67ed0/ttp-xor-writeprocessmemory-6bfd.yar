rule TTP_XOR_WriteProcessMemory_6bfd {
  strings:
    $key_6bfd = { 3c 8f [2] 0e ad [2] 08 98 [2] 26 98 [2] 19 84 }

  condition:
    any of them
}