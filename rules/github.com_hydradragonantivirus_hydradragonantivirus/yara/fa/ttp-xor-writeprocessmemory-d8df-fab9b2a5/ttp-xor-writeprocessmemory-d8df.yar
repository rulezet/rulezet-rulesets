rule TTP_XOR_WriteProcessMemory_d8df {
  strings:
    $key_d8df = { 8f ad [2] bd 8f [2] bb ba [2] 95 ba [2] aa a6 }

  condition:
    any of them
}