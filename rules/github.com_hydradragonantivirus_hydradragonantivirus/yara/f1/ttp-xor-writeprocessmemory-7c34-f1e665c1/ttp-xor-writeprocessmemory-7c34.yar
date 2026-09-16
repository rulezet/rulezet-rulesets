rule TTP_XOR_WriteProcessMemory_7c34 {
  strings:
    $key_7c34 = { 2b 46 [2] 19 64 [2] 1f 51 [2] 31 51 [2] 0e 4d }

  condition:
    any of them
}