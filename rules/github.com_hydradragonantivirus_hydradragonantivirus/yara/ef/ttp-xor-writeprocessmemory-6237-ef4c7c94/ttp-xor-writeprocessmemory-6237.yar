rule TTP_XOR_WriteProcessMemory_6237 {
  strings:
    $key_6237 = { 35 45 [2] 07 67 [2] 01 52 [2] 2f 52 [2] 10 4e }

  condition:
    any of them
}