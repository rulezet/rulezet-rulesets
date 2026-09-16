rule TTP_XOR_WriteProcessMemory_0cfd {
  strings:
    $key_0cfd = { 5b 8f [2] 69 ad [2] 6f 98 [2] 41 98 [2] 7e 84 }

  condition:
    any of them
}