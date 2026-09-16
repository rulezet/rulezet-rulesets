rule TTP_XOR_WriteProcessMemory_0c31 {
  strings:
    $key_0c31 = { 5b 43 [2] 69 61 [2] 6f 54 [2] 41 54 [2] 7e 48 }

  condition:
    any of them
}