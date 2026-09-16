rule TTP_XOR_WriteProcessMemory_03df {
  strings:
    $key_03df = { 54 ad [2] 66 8f [2] 60 ba [2] 4e ba [2] 71 a6 }

  condition:
    any of them
}