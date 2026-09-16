rule TTP_XOR_WriteProcessMemory_7c33 {
  strings:
    $key_7c33 = { 2b 41 [2] 19 63 [2] 1f 56 [2] 31 56 [2] 0e 4a }

  condition:
    any of them
}