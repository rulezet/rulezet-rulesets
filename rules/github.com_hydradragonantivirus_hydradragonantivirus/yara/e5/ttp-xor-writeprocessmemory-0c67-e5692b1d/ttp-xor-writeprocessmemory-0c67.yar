rule TTP_XOR_WriteProcessMemory_0c67 {
  strings:
    $key_0c67 = { 5b 15 [2] 69 37 [2] 6f 02 [2] 41 02 [2] 7e 1e }

  condition:
    any of them
}