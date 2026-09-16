rule TTP_XOR_WriteProcessMemory_6274 {
  strings:
    $key_6274 = { 35 06 [2] 07 24 [2] 01 11 [2] 2f 11 [2] 10 0d }

  condition:
    any of them
}