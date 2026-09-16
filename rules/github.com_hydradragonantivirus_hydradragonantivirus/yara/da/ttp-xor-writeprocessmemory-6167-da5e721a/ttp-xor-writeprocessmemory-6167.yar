rule TTP_XOR_WriteProcessMemory_6167 {
  strings:
    $key_6167 = { 36 15 [2] 04 37 [2] 02 02 [2] 2c 02 [2] 13 1e }

  condition:
    any of them
}