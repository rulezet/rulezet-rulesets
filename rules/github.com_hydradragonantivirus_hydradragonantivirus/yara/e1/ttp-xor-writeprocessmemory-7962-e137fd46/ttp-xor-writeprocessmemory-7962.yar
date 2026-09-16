rule TTP_XOR_WriteProcessMemory_7962 {
  strings:
    $key_7962 = { 2e 10 [2] 1c 32 [2] 1a 07 [2] 34 07 [2] 0b 1b }

  condition:
    any of them
}