rule TTP_XOR_WriteProcessMemory_0eea {
  strings:
    $key_0eea = { 59 98 [2] 6b ba [2] 6d 8f [2] 43 8f [2] 7c 93 }

  condition:
    any of them
}