rule TTP_XOR_WriteProcessMemory_c952 {
  strings:
    $key_c952 = { 9e 20 [2] ac 02 [2] aa 37 [2] 84 37 [2] bb 2b }

  condition:
    any of them
}