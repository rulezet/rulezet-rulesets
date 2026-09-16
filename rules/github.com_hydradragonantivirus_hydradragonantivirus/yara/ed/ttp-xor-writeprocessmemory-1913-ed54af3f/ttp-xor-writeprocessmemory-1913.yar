rule TTP_XOR_WriteProcessMemory_1913 {
  strings:
    $key_1913 = { 4e 61 [2] 7c 43 [2] 7a 76 [2] 54 76 [2] 6b 6a }

  condition:
    any of them
}