rule TTP_XOR_WriteProcessMemory_7e61 {
  strings:
    $key_7e61 = { 29 13 [2] 1b 31 [2] 1d 04 [2] 33 04 [2] 0c 18 }

  condition:
    any of them
}