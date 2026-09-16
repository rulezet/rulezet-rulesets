rule TTP_XOR_WriteProcessMemory_e3df {
  strings:
    $key_e3df = { b4 ad [2] 86 8f [2] 80 ba [2] ae ba [2] 91 a6 }

  condition:
    any of them
}