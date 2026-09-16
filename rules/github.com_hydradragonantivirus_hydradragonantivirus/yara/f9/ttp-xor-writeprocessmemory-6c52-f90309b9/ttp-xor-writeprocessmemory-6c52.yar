rule TTP_XOR_WriteProcessMemory_6c52 {
  strings:
    $key_6c52 = { 3b 20 [2] 09 02 [2] 0f 37 [2] 21 37 [2] 1e 2b }

  condition:
    any of them
}