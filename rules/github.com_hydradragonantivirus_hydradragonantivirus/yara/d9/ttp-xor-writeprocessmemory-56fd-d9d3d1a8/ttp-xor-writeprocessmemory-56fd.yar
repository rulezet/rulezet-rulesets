rule TTP_XOR_WriteProcessMemory_56fd {
  strings:
    $key_56fd = { 01 8f [2] 33 ad [2] 35 98 [2] 1b 98 [2] 24 84 }

  condition:
    any of them
}