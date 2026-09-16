rule TTP_XOR_WriteProcessMemory_1eea {
  strings:
    $key_1eea = { 49 98 [2] 7b ba [2] 7d 8f [2] 53 8f [2] 6c 93 }

  condition:
    any of them
}