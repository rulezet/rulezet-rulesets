rule TTP_XOR_WriteProcessMemory_7c47 {
  strings:
    $key_7c47 = { 2b 35 [2] 19 17 [2] 1f 22 [2] 31 22 [2] 0e 3e }

  condition:
    any of them
}