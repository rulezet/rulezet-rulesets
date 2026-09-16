rule TTP_XOR_WriteProcessMemory_5b53 {
  strings:
    $key_5b53 = { 0c 21 [2] 3e 03 [2] 38 36 [2] 16 36 [2] 29 2a }

  condition:
    any of them
}