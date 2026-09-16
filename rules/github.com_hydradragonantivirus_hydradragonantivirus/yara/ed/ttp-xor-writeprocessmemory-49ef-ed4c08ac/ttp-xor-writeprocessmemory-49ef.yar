rule TTP_XOR_WriteProcessMemory_49ef {
  strings:
    $key_49ef = { 1e 9d [2] 2c bf [2] 2a 8a [2] 04 8a [2] 3b 96 }

  condition:
    any of them
}