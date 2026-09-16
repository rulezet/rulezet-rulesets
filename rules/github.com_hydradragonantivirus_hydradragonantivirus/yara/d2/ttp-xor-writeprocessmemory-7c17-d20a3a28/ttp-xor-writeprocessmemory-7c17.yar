rule TTP_XOR_WriteProcessMemory_7c17 {
  strings:
    $key_7c17 = { 2b 65 [2] 19 47 [2] 1f 72 [2] 31 72 [2] 0e 6e }

  condition:
    any of them
}