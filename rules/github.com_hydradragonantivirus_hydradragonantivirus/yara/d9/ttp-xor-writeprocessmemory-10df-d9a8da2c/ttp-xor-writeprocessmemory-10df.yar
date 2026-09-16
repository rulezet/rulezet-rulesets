rule TTP_XOR_WriteProcessMemory_10df {
  strings:
    $key_10df = { 47 ad [2] 75 8f [2] 73 ba [2] 5d ba [2] 62 a6 }

  condition:
    any of them
}