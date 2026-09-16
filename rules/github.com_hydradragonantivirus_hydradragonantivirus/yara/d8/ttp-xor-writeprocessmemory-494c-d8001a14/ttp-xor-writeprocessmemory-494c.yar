rule TTP_XOR_WriteProcessMemory_494c {
  strings:
    $key_494c = { 1e 3e [2] 2c 1c [2] 2a 29 [2] 04 29 [2] 3b 35 }

  condition:
    any of them
}