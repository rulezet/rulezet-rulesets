rule TTP_XOR_WriteProcessMemory_7b04 {
  strings:
    $key_7b04 = { 2c 76 [2] 1e 54 [2] 18 61 [2] 36 61 [2] 09 7d }

  condition:
    any of them
}