rule TTP_XOR_WriteProcessMemory_3b64 {
  strings:
    $key_3b64 = { 6c 16 [2] 5e 34 [2] 58 01 [2] 76 01 [2] 49 1d }

  condition:
    any of them
}