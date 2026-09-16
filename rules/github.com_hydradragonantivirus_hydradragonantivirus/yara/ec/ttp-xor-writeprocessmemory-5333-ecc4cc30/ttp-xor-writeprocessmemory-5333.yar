rule TTP_XOR_WriteProcessMemory_5333 {
  strings:
    $key_5333 = { 04 41 [2] 36 63 [2] 30 56 [2] 1e 56 [2] 21 4a }

  condition:
    any of them
}