rule TTP_XOR_WriteProcessMemory_1cfd {
  strings:
    $key_1cfd = { 4b 8f [2] 79 ad [2] 7f 98 [2] 51 98 [2] 6e 84 }

  condition:
    any of them
}