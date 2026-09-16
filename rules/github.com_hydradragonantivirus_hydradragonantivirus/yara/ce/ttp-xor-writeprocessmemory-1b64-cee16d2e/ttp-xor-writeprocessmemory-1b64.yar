rule TTP_XOR_WriteProcessMemory_1b64 {
  strings:
    $key_1b64 = { 4c 16 [2] 7e 34 [2] 78 01 [2] 56 01 [2] 69 1d }

  condition:
    any of them
}