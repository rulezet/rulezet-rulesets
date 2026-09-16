rule TTP_XOR_WriteProcessMemory_6961 {
  strings:
    $key_6961 = { 3e 13 [2] 0c 31 [2] 0a 04 [2] 24 04 [2] 1b 18 }

  condition:
    any of them
}