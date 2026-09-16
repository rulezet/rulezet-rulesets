rule TTP_XOR_WriteProcessMemory_ef64 {
  strings:
    $key_ef64 = { b8 16 [2] 8a 34 [2] 8c 01 [2] a2 01 [2] 9d 1d }

  condition:
    any of them
}