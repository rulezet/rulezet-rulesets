rule TTP_XOR_WriteProcessMemory_e95d {
  strings:
    $key_e95d = { be 2f [2] 8c 0d [2] 8a 38 [2] a4 38 [2] 9b 24 }

  condition:
    any of them
}