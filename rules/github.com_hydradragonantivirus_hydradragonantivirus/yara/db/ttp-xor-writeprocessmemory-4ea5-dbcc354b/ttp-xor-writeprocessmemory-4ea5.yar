rule TTP_XOR_WriteProcessMemory_4ea5 {
  strings:
    $key_4ea5 = { 19 d7 [2] 2b f5 [2] 2d c0 [2] 03 c0 [2] 3c dc }

  condition:
    any of them
}