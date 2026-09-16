rule TTP_XOR_WriteProcessMemory_7c67 {
  strings:
    $key_7c67 = { 2b 15 [2] 19 37 [2] 1f 02 [2] 31 02 [2] 0e 1e }

  condition:
    any of them
}