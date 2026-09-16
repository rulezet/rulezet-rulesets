rule TTP_XOR_WriteProcessMemory_7c20 {
  strings:
    $key_7c20 = { 2b 52 [2] 19 70 [2] 1f 45 [2] 31 45 [2] 0e 59 }

  condition:
    any of them
}