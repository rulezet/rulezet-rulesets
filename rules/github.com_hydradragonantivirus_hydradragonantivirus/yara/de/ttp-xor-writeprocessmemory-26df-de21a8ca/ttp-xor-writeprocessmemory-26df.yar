rule TTP_XOR_WriteProcessMemory_26df {
  strings:
    $key_26df = { 71 ad [2] 43 8f [2] 45 ba [2] 6b ba [2] 54 a6 }

  condition:
    any of them
}