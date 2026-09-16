rule TTP_XOR_WriteProcessMemory_7c52 {
  strings:
    $key_7c52 = { 2b 20 [2] 19 02 [2] 1f 37 [2] 31 37 [2] 0e 2b }

  condition:
    any of them
}