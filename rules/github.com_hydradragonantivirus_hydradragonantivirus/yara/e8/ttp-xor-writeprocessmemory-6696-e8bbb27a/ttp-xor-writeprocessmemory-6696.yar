rule TTP_XOR_WriteProcessMemory_6696 {
  strings:
    $key_6696 = { 31 e4 [2] 03 c6 [2] 05 f3 [2] 2b f3 [2] 14 ef }

  condition:
    any of them
}