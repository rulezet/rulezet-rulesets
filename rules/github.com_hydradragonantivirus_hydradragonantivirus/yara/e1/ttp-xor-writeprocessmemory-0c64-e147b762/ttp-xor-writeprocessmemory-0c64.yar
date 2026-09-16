rule TTP_XOR_WriteProcessMemory_0c64 {
  strings:
    $key_0c64 = { 5b 16 [2] 69 34 [2] 6f 01 [2] 41 01 [2] 7e 1d }

  condition:
    any of them
}