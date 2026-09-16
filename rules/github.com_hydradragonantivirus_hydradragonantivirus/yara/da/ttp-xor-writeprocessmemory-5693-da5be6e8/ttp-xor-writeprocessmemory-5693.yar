rule TTP_XOR_WriteProcessMemory_5693 {
  strings:
    $key_5693 = { 01 e1 [2] 33 c3 [2] 35 f6 [2] 1b f6 [2] 24 ea }

  condition:
    any of them
}