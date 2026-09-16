rule TTP_XOR_WriteProcessMemory_76df {
  strings:
    $key_76df = { 21 ad [2] 13 8f [2] 15 ba [2] 3b ba [2] 04 a6 }

  condition:
    any of them
}