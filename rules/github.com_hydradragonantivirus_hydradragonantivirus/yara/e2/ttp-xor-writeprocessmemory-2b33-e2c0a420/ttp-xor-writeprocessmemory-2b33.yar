rule TTP_XOR_WriteProcessMemory_2b33 {
  strings:
    $key_2b33 = { 7c 41 [2] 4e 63 [2] 48 56 [2] 66 56 [2] 59 4a }

  condition:
    any of them
}