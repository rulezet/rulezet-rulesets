rule TTP_XOR_WriteProcessMemory_eea2 {
  strings:
    $key_eea2 = { b9 d0 [2] 8b f2 [2] 8d c7 [2] a3 c7 [2] 9c db }

  condition:
    any of them
}